package admin

import (
	"sort"
	"strconv"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/auditlog"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/eventtype"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
)

const (
	auditUserCondition  = "audit_user"
	auditActionConition = "audit_action"
	auditTypeCondition  = "type"
)

type (
	// AuditListService lists site-wide audit logs.
	AuditListService struct {
		Page           int               `json:"page" binding:"min=1"`
		PageSize       int               `json:"page_size" binding:"min=10,max=100"`
		OrderBy        string            `json:"order_by"`
		OrderDirection string            `json:"order_direction"`
		Conditions     map[string]string `json:"conditions"`
	}
	AuditListParamCtx struct{}

	// AuditLogItem mirrors the Pro event record shape.
	AuditLogItem struct {
		ID            int               `json:"id"`
		CreatedAt     string            `json:"created_at"`
		UpdatedAt     string            `json:"updated_at"`
		Type          int               `json:"type"`
		Action        string            `json:"action"`
		CorrelationID string            `json:"correlation_id,omitempty"`
		IP            string            `json:"ip"`
		Content       map[string]interface{} `json:"content"`
		Edges         AuditLogUserEdge  `json:"edges"`
		UserHashID    string            `json:"user_hash_id"`
		// Legacy fields kept for compatibility with the magic-edition UI.
		UserID    int    `json:"user_id"`
		UserEmail string `json:"user_email"`
		ObjType   string `json:"object_type"`
		ObjName   string `json:"object_name"`
		Detail    string `json:"detail"`
	}

	AuditLogUserEdge struct {
		User *ent.User `json:"user,omitempty"`
	}

	AuditListResponse struct {
		Pagination *inventory.PaginationResults `json:"pagination"`
		Logs       []AuditLogItem               `json:"logs"`
	}

	// AuditBatchDeleteService batch deletes audit logs.
	AuditBatchDeleteService struct {
		ID []uint `json:"ids" binding:"min=1"`
	}
	AuditBatchDeleteParamCtx struct{}

	// AuditCleanupService deletes audit logs matching the given criteria.
	AuditCleanupService struct {
		Types      []string `json:"types"`
		BeforeDays int      `json:"before_days" binding:"min=1"`
	}
	AuditCleanupParamCtx struct{}

	// SingleAuditService fetches one audit log by (hash) ID.
	SingleAuditService struct {
		ID string `uri:"id" binding:"required"`
	}
	SingleAuditParamCtx struct{}
)

func (service *AuditListService) buildQuery(c *gin.Context) (*ent.AuditLogQuery, error) {
	dep := dependency.FromContext(c)
	hasher := dep.HashIDEncoder()
	db := dep.DBClient()

	query := db.AuditLog.Query()

	if uid := service.Conditions[auditUserCondition]; uid != "" {
		if parsed, err := strconv.Atoi(uid); err == nil {
			query = query.Where(auditlog.UserIDEQ(parsed))
		} else if decoded, derr := hasher.Decode(uid, hashid.UserID); derr == nil {
			query = query.Where(auditlog.UserIDEQ(decoded))
		} else {
			return nil, serializer.NewError(serializer.CodeParamErr, "Invalid user ID", nil)
		}
	}
	if action := service.Conditions[auditActionConition]; action != "" {
		// Accept both numeric type and canonical action name.
		if t, err := strconv.Atoi(action); err == nil {
			query = query.Where(auditlog.TypeEQ(t))
		} else if tp, ok := eventtype.FromName(action); ok {
			query = query.Where(auditlog.TypeEQ(int(tp)))
		} else {
			query = query.Where(auditlog.ActionEQ(action))
		}
	}
	if t := service.Conditions[auditTypeCondition]; t != "" {
		if tp, err := strconv.Atoi(t); err == nil {
			query = query.Where(auditlog.TypeEQ(tp))
		}
	}

	if service.OrderBy != "" {
		if service.OrderDirection == "asc" {
			query = query.Order(ent.Asc(service.OrderBy))
		} else {
			query = query.Order(ent.Desc(service.OrderBy))
		}
	} else {
		query = query.Order(ent.Desc(auditlog.FieldCreatedAt))
	}
	return query, nil
}

// List returns paginated audit logs (Pro /admin/event shape).
func (service *AuditListService) List(c *gin.Context) (*AuditListResponse, error) {
	dep := dependency.FromContext(c)
	hasher := dep.HashIDEncoder()

	query, err := service.buildQuery(c)
	if err != nil {
		return nil, err
	}
	total, err := query.Clone().Count(c)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "failed to count audit logs", err)
	}
	logs, err := query.
		WithUser().
		Limit(service.PageSize).Offset((service.Page - 1) * service.PageSize).All(c)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "failed to list audit logs", err)
	}

	items := make([]AuditLogItem, 0, len(logs))
	for _, l := range logs {
		items = append(items, AuditLogItem{
			ID:            l.ID,
			CreatedAt:     l.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     l.UpdatedAt.Format(time.RFC3339),
			Type:          l.Type,
			Action:        l.Action,
			CorrelationID: l.CorrelationID,
			IP:            l.IP,
			Content:       l.Content,
			Edges:         AuditLogUserEdge{User: l.Edges.User},
			UserHashID:    hashid.EncodeUserID(hasher, l.UserID),
			UserID:        l.UserID,
			UserEmail:     l.UserEmail,
			ObjType:       l.ObjectType,
			ObjName:       l.ObjectName,
			Detail:        l.Detail,
		})
	}

	return &AuditListResponse{
		Pagination: &inventory.PaginationResults{
			TotalItems: total,
			Page:       service.Page - 1,
			PageSize:   service.PageSize,
		},
		Logs: items,
	}, nil
}

// Get returns a single audit log entry.
func (service *SingleAuditService) Get(c *gin.Context) (*AuditLogItem, error) {
	dep := dependency.FromContext(c)
	hasher := dep.HashIDEncoder()
	db := dep.DBClient()

	id, err := hasher.Decode(service.ID, hashid.AuditLogID)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeNotFound, "audit log not found", err)
	}
	l, err := db.AuditLog.Query().Where(auditlog.IDEQ(id)).WithUser().First(c)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeNotFound, "audit log not found", err)
	}
	item := AuditLogItem{
		ID:        l.ID,
		CreatedAt: l.CreatedAt.Format(time.RFC3339),
		UpdatedAt: l.UpdatedAt.Format(time.RFC3339),
		Type:      l.Type,
		Action:    l.Action,
		IP:        l.IP,
		Content:   l.Content,
		Edges:     AuditLogUserEdge{User: l.Edges.User},
		UserHashID: hashid.EncodeUserID(hasher, l.UserID),
		UserID:    l.UserID,
		UserEmail: l.UserEmail,
		ObjType:   l.ObjectType,
		ObjName:   l.ObjectName,
		Detail:    l.Detail,
	}
	return &item, nil
}

// BatchDelete removes audit logs by IDs.
func (service *AuditBatchDeleteService) BatchDelete(c *gin.Context) error {
	dep := dependency.FromContext(c)
	db := dep.DBClient()
	ids := lo.Map(service.ID, func(i uint, _ int) int { return int(i) })
	if _, err := db.AuditLog.Delete().Where(auditlog.IDIn(ids...)).Exec(c); err != nil {
		return serializer.NewError(serializer.CodeDBError, "failed to delete audit logs", err)
	}
	return nil
}

// Cleanup removes audit logs older than BeforeDays, optionally restricted
// to given event type names.
func (service *AuditCleanupService) Cleanup(c *gin.Context) error {
	dep := dependency.FromContext(c)
	db := dep.DBClient()

	cutoff := time.Now().AddDate(0, 0, -service.BeforeDays)
	query := db.AuditLog.Delete().Where(auditlog.CreatedAtLT(cutoff))
	if len(service.Types) > 0 {
		types := make([]int, 0, len(service.Types))
		for _, name := range service.Types {
			if t, ok := eventtype.FromName(name); ok {
				types = append(types, int(t))
			}
		}
		if len(types) > 0 {
			query = query.Where(auditlog.TypeIn(types...))
		}
	}
	if _, err := query.Exec(c); err != nil {
		return serializer.NewError(serializer.CodeDBError, "failed to cleanup audit logs", err)
	}
	return nil
}

// AllEventTypes exposes the full event type name list (for frontend filters).
func AllEventTypes() []string {
	names := make([]string, 0, 62)
	for i := 0; i <= 61; i++ {
		names = append(names, eventtype.EventType(i).Name())
	}
	sort.Strings(names)
	return names
}
