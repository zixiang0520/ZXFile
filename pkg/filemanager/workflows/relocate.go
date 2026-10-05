package workflows

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"path"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/driver"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs/dbfs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/queue"
	"github.com/cloudreve/Cloudreve/v4/pkg/util"
)

// Relocate migrates files (all entities incl. historical versions) from their
// current storage policy to a new one. This re-implements the Pro-only
// "storage policy migration" feature on top of the open-source codebase.
const (
	RelocateProgressTypeEntity = "relocated"
	RelocateProgressTypeSize   = "relocate_size"

	SummaryKeyRelocateDstPolicyID = "dst_policy_id"
	SummaryKeyRelocateSrc         = "src_str"
	SummaryKeyRelocateFailed      = "failed"

	RelocateBatchSize = 50
)

type (
	RelocateTaskPhase string
)

const (
	RelocateTaskPhasePrepare   RelocateTaskPhase = "prepare"
	RelocateTaskPhaseExecute   RelocateTaskPhase = "execute"
	RelocateTaskPhaseCompleted RelocateTaskPhase = "completed"
)

type (
	RelocateTask struct {
		*queue.DBTask

		l        logging.Logger
		state    *RelocateTaskState
		progress queue.Progresses
		planMut  sync.Mutex
		plan     []*relocatePlanEntry
	}

	RelocateTaskState struct {
		SrcUris     []string          `json:"src_uris,omitempty"`
		FileIDs     []int             `json:"file_ids,omitempty"`
		DstPolicyID int               `json:"dst_policy_id"`
		Phase       RelocateTaskPhase `json:"phase"`
		Failed      int               `json:"failed,omitempty"`
		// Number of entities already migrated, used to skip finished entries on resume.
		Done int `json:"done,omitempty"`
	}

	// relocatePlanEntry is one entity to be migrated.
	relocatePlanEntry struct {
		EntityID    int    `json:"entity_id"`
		OldSource   string `json:"old_source"`
		OldPolicyID int    `json:"old_policy_id"`
		NewSavePath string `json:"new_save_path"`
		Size        int64  `json:"size"`
		DisplayName string `json:"display_name"`
		Done        bool   `json:"done"`
	}
)

func init() {
	queue.RegisterResumableTaskFactory(queue.RelocateTaskType, NewRelocateTaskFromModel)
}

func NewRelocateTask(ctx context.Context, u *ent.User, srcUris []string, fileIDs []int, dstPolicyID int) (queue.Task, error) {
	state := &RelocateTaskState{
		SrcUris:     srcUris,
		FileIDs:     fileIDs,
		DstPolicyID: dstPolicyID,
	}
	stateBytes, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal state: %w", err)
	}

	t := &RelocateTask{
		DBTask: &queue.DBTask{
			Task: &ent.Task{
				Type:          queue.RelocateTaskType,
				CorrelationID: logging.CorrelationID(ctx),
				PrivateState:  string(stateBytes),
				PublicState:   &types.TaskPublicState{},
			},
			DirectOwner: u,
		},
	}
	return t, nil
}

func NewRelocateTaskFromModel(task *ent.Task) queue.Task {
	return &RelocateTask{
		DBTask: &queue.DBTask{
			Task: task,
		},
	}
}

func (m *RelocateTask) Do(ctx context.Context) (task.Status, error) {
	dep := dependency.FromContext(ctx)
	m.l = dep.Logger()

	m.Lock()
	if m.progress == nil {
		m.progress = make(queue.Progresses)
	}
	m.Unlock()

	state := &RelocateTaskState{}
	if err := json.Unmarshal([]byte(m.State()), state); err != nil {
		return task.StatusError, fmt.Errorf("failed to unmarshal state: %w", err)
	}
	m.state = state

	next, err := m.processRelocate(ctx, dep)

	newStateStr, marshalErr := json.Marshal(m.state)
	if marshalErr != nil {
		return task.StatusError, fmt.Errorf("failed to marshal state: %w", marshalErr)
	}

	m.Lock()
	m.Task.PrivateState = string(newStateStr)
	m.Unlock()
	return next, err
}

func (m *RelocateTask) processRelocate(ctx context.Context, dep dependency.Dep) (task.Status, error) {
	user := inventory.UserFromContext(ctx)

	switch m.state.Phase {
	case "", RelocateTaskPhasePrepare:
		// Build the plan then execute within the same Do invocation. If the
		// process crashes mid-way, resuming re-runs prepare, and entities
		// already on the dst policy are skipped (idempotent resume).
		next, err := m.prepare(ctx, dep, user)
		if err != nil || next != task.StatusSuspending {
			return next, err
		}
		return m.execute(ctx, dep, user)
	case RelocateTaskPhaseExecute:
		return m.execute(ctx, dep, user)
	default:
		m.l.Warning("Unknown relocate phase %q, mark as completed.", m.state.Phase)
		return task.StatusCompleted, nil
	}
}

// prepare builds the migration plan either from explicit file IDs (admin
// panel batch mode, ownership bypassed) or by walking the source URIs.
func (m *RelocateTask) prepare(ctx context.Context, dep dependency.Dep, user *ent.User) (task.Status, error) {
	dstPolicy, err := dep.StoragePolicyClient().GetPolicyByID(ctx, m.state.DstPolicyID)
	if err != nil {
		return task.StatusError, fmt.Errorf("failed to get dst policy (%w)", queue.CriticalErr)
	}

	plan := make([]*relocatePlanEntry, 0)

	if len(m.state.FileIDs) > 0 {
		// Admin batch mode: load files by ID directly, bypassing ownership.
		fm := manager.NewFileManager(dep, user)
		defer fm.Recycle()

		for batchStart := 0; batchStart < len(m.state.FileIDs); batchStart += RelocateBatchSize {
			batchEnd := min(batchStart+RelocateBatchSize, len(m.state.FileIDs))
			batch := m.state.FileIDs[batchStart:batchEnd]

			files, err := dep.DBClient().File.Query().
				Where(file.IDIn(batch...)).
				WithEntities().
				All(ctx)
			if err != nil {
				return task.StatusError, fmt.Errorf("failed to load files by ID: %w", err)
			}

			for _, f := range files {
				if f == nil || f.Type != int(types.FileTypeFile) {
					continue
				}
				for _, e := range f.Edges.Entities {
					if e == nil || e.ReferenceCount == 0 {
						continue
					}
					plan = append(plan, &relocatePlanEntry{
						EntityID:    e.ID,
						OldSource:   e.Source,
						OldPolicyID: e.StoragePolicyEntities,
						NewSavePath: relocateSavePath(dstPolicy, f.Name, "/", user),
						Size:        e.Size,
						DisplayName: f.Name,
					})
				}
			}
		}
	} else {
		if err := m.walkSources(ctx, dep, user, dstPolicy, &plan); err != nil {
			return task.StatusError, err
		}
	}

	// Files already stored under the destination policy don't need physical transfer.
	finalPlan := make([]*relocatePlanEntry, 0, len(plan))
	for _, p := range plan {
		if p.OldPolicyID == m.state.DstPolicyID {
			m.l.Info("Entity #%d already on policy #%d, skipping.", p.EntityID, p.OldPolicyID)
			continue
		}
		finalPlan = append(finalPlan, p)
	}

	m.planMut.Lock()
	m.plan = finalPlan
	m.planMut.Unlock()

	var totalSize int64
	for _, p := range finalPlan {
		totalSize += p.Size
	}

	m.l.Info("Relocate plan: %d entities (%d bytes) to migrate to policy #%d.",
		len(finalPlan), totalSize, m.state.DstPolicyID)

	m.Lock()
	m.progress[RelocateProgressTypeEntity] = &queue.Progress{Total: int64(len(finalPlan))}
	m.progress[RelocateProgressTypeSize] = &queue.Progress{Total: totalSize}
	m.Unlock()

	// Nothing to do, complete immediately.
	if len(finalPlan) == 0 {
		return task.StatusCompleted, nil
	}

	m.state.Phase = RelocateTaskPhaseExecute
	return task.StatusSuspending, nil
}

// walkSources walks the source URIs and appends per-entity plan entries.
func (m *RelocateTask) walkSources(ctx context.Context, dep dependency.Dep, user *ent.User,
	dstPolicy *ent.StoragePolicy, plan *[]*relocatePlanEntry) error {
	fm := manager.NewFileManager(dep, user)
	defer fm.Recycle()

	for _, srcUri := range m.state.SrcUris {
		if err := ctx.Err(); err != nil {
			return err
		}

		uri, err := fs.NewUriFromString(srcUri)
		if err != nil {
			m.l.Warning("Skipping invalid src uri %q: %s", srcUri, err)
			m.state.Failed++
			continue
		}

		if err := fm.Walk(ctx, uri, math.MaxInt32, func(f fs.File, level int) error {
			if f.Type() != types.FileTypeFile || f.IsSymbolic() {
				return nil
			}
			for _, e := range f.Entities() {
				if e.ReferenceCount() == 0 {
					continue
				}
				*plan = append(*plan, &relocatePlanEntry{
					EntityID:    e.ID(),
					OldSource:   e.Source(),
					OldPolicyID: e.PolicyID(),
					NewSavePath: relocateSavePath(dstPolicy, f.DisplayName(), uri.Dir(), user),
					Size:        e.Size(),
					DisplayName: f.DisplayName(),
				})
			}
			return nil
		}, dbfs.WithFileEntities()); err != nil {
			m.l.Warning("Failed to walk %q: %s", srcUri, err)
			m.state.Failed++
		}
	}
	return nil
}

// execute performs the actual data transfer with bounded concurrency.
func (m *RelocateTask) execute(ctx context.Context, dep dependency.Dep, user *ent.User) (task.Status, error) {
	m.planMut.Lock()
	plan := m.plan
	m.planMut.Unlock()

	if plan == nil {
		return task.StatusError, fmt.Errorf("relocate plan is missing (%w)", queue.CriticalErr)
	}

	dstPolicy, err := dep.StoragePolicyClient().GetPolicyByID(ctx, m.state.DstPolicyID)
	if err != nil {
		return task.StatusError, fmt.Errorf("failed to get dst policy: %w", err)
	}
	dstDriver, err := manager.NewFileManager(dep, user).GetStorageDriver(ctx, dstPolicy)
	if err != nil {
		return task.StatusError, fmt.Errorf("failed to initialize dst driver: %w (%w)", err, queue.CriticalErr)
	}

	maxParallel := int(dep.SettingProvider().MaxParallelTransfer(ctx))
	if maxParallel < 1 {
		maxParallel = 1
	}
	if maxParallel > len(plan) {
		maxParallel = len(plan)
	}

	wg := sync.WaitGroup{}
	worker := make(chan int, maxParallel)
	for i := 0; i < maxParallel; i++ {
		worker <- i
	}

	failed := atomic.Int64{}
	var failedMu sync.Mutex
	firstErrs := make([]string, 0, 5)

	var doneEntities, doneSize atomic.Int64

	transferFunc := func(workerId int, entry *relocatePlanEntry) {
		defer func() {
			worker <- workerId
			wg.Done()
		}()

		if err := m.relocateOne(ctx, dep, user, dstPolicy, dstDriver, entry); err != nil {
			failedMu.Lock()
			if len(firstErrs) < 5 {
				firstErrs = append(firstErrs, fmt.Sprintf("%s: %s", entry.DisplayName, err))
			}
			failedMu.Unlock()
			failed.Add(1)
			m.l.Warning("Failed to relocate entity #%d (%s): %s", entry.EntityID, entry.DisplayName, err)
			return
		}

		entry.Done = true
		m.state.Done++
		doneEntities.Add(1)
		doneSize.Add(entry.Size)
		m.Lock()
		if p, ok := m.progress[RelocateProgressTypeEntity]; ok {
			p.Current = doneEntities.Load()
		}
		if p, ok := m.progress[RelocateProgressTypeSize]; ok {
			p.Current = doneSize.Load()
		}
		m.Unlock()
	}

	for _, entry := range plan {
		if entry.Done {
			continue
		}

		select {
		case <-ctx.Done():
			wg.Wait()
			m.state.Failed = int(failed.Load())
			return task.StatusError, ctx.Err()
		case workerId := <-worker:
			wg.Add(1)
			go transferFunc(workerId, entry)
		}
	}
	wg.Wait()

	m.state.Failed += int(failed.Load())
	if failed.Load() > 0 {
		return task.StatusError, fmt.Errorf("failed to relocate %d entities, first errors: %s",
			failed.Load(), firstErrs)
	}

	m.l.Info("All entities relocated to policy #%d.", m.state.DstPolicyID)
	m.state.Phase = RelocateTaskPhaseCompleted
	return task.StatusCompleted, nil
}

// relocateOne migrates a single entity: source -> dst driver -> DB update -> cleanup.
func (m *RelocateTask) relocateOne(ctx context.Context, dep dependency.Dep, user *ent.User,
	dstPolicy *ent.StoragePolicy, dstDriver driver.Handler, entry *relocatePlanEntry) error {
	fm := manager.NewFileManager(dep, user)
	defer fm.Recycle()

	// 1. Open source content stream.
	src, err := fm.GetEntitySource(ctx, entry.EntityID)
	if err != nil {
		return fmt.Errorf("failed to open entity source: %w", err)
	}
	defer src.Close()

	// 2. Upload raw content to destination policy.
	req := &fs.UploadRequest{
		Props: &fs.UploadProps{
			SavePath: entry.NewSavePath,
			Size:     entry.Size,
		},
		File: src,
	}
	if err := dstDriver.Put(ctx, req); err != nil {
		return fmt.Errorf("failed to put to new policy: %w", err)
	}

	// 3. Update entity to point to the new storage.
	dbClient := dep.DBClient()
	if _, err := dbClient.Entity.UpdateOneID(entry.EntityID).
		SetStoragePolicyEntities(m.state.DstPolicyID).
		SetSource(entry.NewSavePath).
		Save(ctx); err != nil {
		// Rollback the uploaded physical file to avoid orphans.
		if failed, dErr := dstDriver.Delete(ctx, entry.NewSavePath); dErr != nil {
			m.l.Warning("Failed to cleanup orphaned new file %q after DB error: %v (failed: %v)",
				entry.NewSavePath, dErr, failed)
		}
		return fmt.Errorf("failed to update entity #%d: %w", entry.EntityID, err)
	}

	// 4. Delete the old physical file from the old policy.
	if entry.OldPolicyID != 0 {
		oldPolicy, err := dep.StoragePolicyClient().GetPolicyByID(ctx, entry.OldPolicyID)
		if err != nil {
			m.l.Warning("Failed to get old policy #%d for cleanup of %q: %s",
				entry.OldPolicyID, entry.OldSource, err)
		} else {
			oldDriver, err := fm.GetStorageDriver(ctx, oldPolicy)
			if err != nil {
				m.l.Warning("Failed to initialize old driver for cleanup of %q: %s", entry.OldSource, err)
			} else if failed, err := oldDriver.Delete(ctx, entry.OldSource); err != nil {
				m.l.Warning("Failed to delete old physical file %q: %s (failed: %v)",
					entry.OldSource, err, failed)
			}
		}
	}

	m.l.Info("Relocated entity #%d (%s): %q -> %q",
		entry.EntityID, entry.DisplayName, entry.OldSource, entry.NewSavePath)
	return nil
}

// relocateSavePath generates the physical save path under dstPolicy, mirroring
// dbfs.generateSavePath.
func relocateSavePath(dstPolicy *ent.StoragePolicy, displayName, dirPath string, user *ent.User) string {
	currentTime := time.Now()
	dynamicReplace := func(rule string, pathAvailable bool) string {
		return util.ReplaceMagicVar(rule, fs.Separator, pathAvailable, false,
			currentTime, user.ID, displayName, dirPath, "")
	}

	dirRule := filepath.ToSlash(dstPolicy.DirNameRule)
	dirRule = dynamicReplace(dirRule, true)
	nameRule := dynamicReplace(dstPolicy.FileNameRule, false)
	return path.Join(path.Clean(dirRule), nameRule)
}

func (m *RelocateTask) Progress(ctx context.Context) queue.Progresses {
	m.Lock()
	defer m.Unlock()
	return m.progress
}

func (m *RelocateTask) Summarize(hasher hashid.Encoder) *queue.Summary {
	if m.state == nil {
		if err := json.Unmarshal([]byte(m.State()), &m.state); err != nil {
			return nil
		}
	}

	return &queue.Summary{
		Phase: string(m.state.Phase),
		Props: map[string]any{
			SummaryKeyRelocateSrc:         fmt.Sprintf("%v", m.state.SrcUris),
			SummaryKeyRelocateDstPolicyID: hashid.EncodePolicyID(hasher, m.state.DstPolicyID),
			SummaryKeyRelocateFailed:      m.state.Failed,
		},
	}
}
