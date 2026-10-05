package admin

import (
	"sort"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/entity"
	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
)

// FileStatsService aggregates file usage metrics for the admin file manager.
type FileStatsService struct{}

type (
	// FileStatsResponse overall + per-user + per-policy aggregation.
	FileStatsResponse struct {
		TotalFiles    int              `json:"total_files"`
		TotalFolders  int              `json:"total_folders"`
		TotalSize     int64            `json:"total_size"`
		UserStats     []UserFileStat   `json:"user_stats"`
		PolicyStats   []PolicyFileStat `json:"policy_stats"`
		RecentUploads []FileBrief      `json:"recent_uploads"`
	}

	// UserFileStat per-user aggregation, sorted by total size desc.
	UserFileStat struct {
		UserID    int    `json:"user_id"`
		UserHash  string `json:"user_hash"`
		Email     string `json:"email"`
		Nickname  string `json:"nickname"`
		FileCount int    `json:"file_count"`
		FolderNum int    `json:"folder_num"`
		TotalSize int64  `json:"total_size"`
	}

	// PolicyFileStat per-storage-policy aggregation.
	PolicyFileStat struct {
		PolicyID  int    `json:"policy_id"`
		Name      string `json:"name"`
		FileCount int    `json:"file_count"`
		TotalSize int64  `json:"total_size"`
	}

	// FileBrief brief file info for recent uploads.
	FileBrief struct {
		ID        int    `json:"id"`
		FileHash  string `json:"file_hash"`
		Name      string `json:"name"`
		Size      int64  `json:"size"`
		OwnerID   int    `json:"owner_id"`
		OwnerName string `json:"owner_name"`
		CreatedAt string `json:"created_at"`
	}
)

type fileAggFloatRow struct {
	OwnerID int     `json:"owner_id"`
	Count   int     `json:"count"`
	Size    float64 `json:"size"`
}

// Get aggregates file stats for the whole site.
func (service *FileStatsService) Get(c *gin.Context) (*FileStatsResponse, error) {
	dep := dependency.FromContext(c)
	hasher := dep.HashIDEncoder()
	db := dep.DBClient()
	ctx := c

	notRoot := file.NameNEQ(inventory.RootFolderName)
	res := &FileStatsResponse{
		UserStats:     make([]UserFileStat, 0),
		PolicyStats:   make([]PolicyFileStat, 0),
		RecentUploads: make([]FileBrief, 0),
	}

	// Global counters.
	var err error
	if res.TotalFiles, err = db.File.Query().
		Where(file.Type(int(types.FileTypeFile)), file.IsSymbolic(false), notRoot).
		Count(ctx); err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "failed to count files", err)
	}
	if res.TotalFolders, err = db.File.Query().
		Where(file.Type(int(types.FileTypeFolder)), file.IsSymbolic(false), notRoot).
		Count(ctx); err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "failed to count folders", err)
	}

	// Per-user aggregation: two group-by queries (files, folders), then merge.
	// NOTE: SQLite SUM returns float, scan into float64 then convert.
	var fileAgg, folderAgg []fileAggFloatRow
	if err := db.File.Query().
		Where(file.Type(int(types.FileTypeFile)), file.IsSymbolic(false), notRoot).
		GroupBy(file.FieldOwnerID).
		Aggregate(
			ent.As(ent.Count(), "count"),
			ent.As(ent.Sum(file.FieldSize), "size"),
		).
		Scan(ctx, &fileAgg); err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "failed to aggregate user file stats", err)
	}
	if err := db.File.Query().
		Where(file.Type(int(types.FileTypeFolder)), file.IsSymbolic(false), notRoot).
		GroupBy(file.FieldOwnerID).
		Aggregate(ent.As(ent.Count(), "count")).
		Scan(ctx, &folderAgg); err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "failed to aggregate user folder stats", err)
	}

	merge := make(map[int]*UserFileStat)
	for _, r := range fileAgg {
		merge[r.OwnerID] = &UserFileStat{UserID: r.OwnerID, FileCount: int(r.Count), TotalSize: int64(r.Size)}
	}
	for _, r := range folderAgg {
		if m, ok := merge[r.OwnerID]; ok {
			m.FolderNum = int(r.Count)
		} else {
			merge[r.OwnerID] = &UserFileStat{UserID: r.OwnerID, FolderNum: int(r.Count)}
		}
	}

	// Load users for email/nickname.
	userIDs := lo.Map(lo.Values(merge), func(r *UserFileStat, _ int) int { return r.UserID })
	users, err := db.User.Query().Where(user.IDIn(userIDs...)).All(ctx)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "failed to load users", err)
	}
	userMap := lo.KeyBy(users, func(u *ent.User) int { return u.ID })

	for _, row := range lo.Values(merge) {
		nickname, email := "", ""
		if u := userMap[row.UserID]; u != nil {
			nickname, email = u.Nick, u.Email
		}
		row.Nickname, row.Email = nickname, email
		row.UserHash = hashid.EncodeUserID(hasher, row.UserID)
		res.UserStats = append(res.UserStats, *row)
	}
	sort.Slice(res.UserStats, func(i, j int) bool {
		return res.UserStats[i].TotalSize > res.UserStats[j].TotalSize
	})

	// Per-policy aggregation: count + size per policy via entity relation.
	policies, err := dep.StoragePolicyClient().ListPolicies(ctx, &inventory.ListPolicyParameters{
		PaginationArgs: &inventory.PaginationArgs{Page: 0, PageSize: 1000},
	})
	if err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "failed to load policies", err)
	}
	var policySizeAgg []struct {
		Size float64 `json:"size"`
	}
	for _, p := range policies.Policies {
		base := db.File.Query().
			Where(
				file.Type(int(types.FileTypeFile)),
				file.IsSymbolic(false),
				file.HasEntitiesWith(entity.StoragePolicyEntitiesEQ(p.ID)),
			)
		count, err := base.Clone().Count(ctx)
		if err != nil {
			continue
		}
		// Reliable fallback: sum sizes in Go (Select only the size column).
		var size int64
		if rows, err := base.Clone().Select(file.FieldSize).All(ctx); err == nil {
			for _, rf := range rows {
				size += rf.Size
			}
		}
		_ = policySizeAgg
		res.PolicyStats = append(res.PolicyStats, PolicyFileStat{
			PolicyID:  p.ID,
			Name:      p.Name,
			FileCount: count,
			TotalSize: size,
		})
		res.TotalSize += size
	}
	sort.Slice(res.PolicyStats, func(i, j int) bool {
		return res.PolicyStats[i].TotalSize > res.PolicyStats[j].TotalSize
	})

	// Recent uploads (latest 10 files).
	recent, err := db.File.Query().
		Where(file.Type(int(types.FileTypeFile)), file.IsSymbolic(false), notRoot).
		Order(ent.Desc(file.FieldCreatedAt)).
		Limit(10).
		All(ctx)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "failed to load recent uploads", err)
	}
	for _, rf := range recent {
		ownerName := ""
		if u := userMap[rf.OwnerID]; u != nil {
			ownerName = u.Nick
		}
		res.RecentUploads = append(res.RecentUploads, FileBrief{
			ID:        rf.ID,
			FileHash:  hashid.EncodeFileID(hasher, rf.ID),
			Name:      rf.Name,
			Size:      rf.Size,
			OwnerID:   rf.OwnerID,
			OwnerName: ownerName,
			CreatedAt: rf.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}

	return res, nil
}
