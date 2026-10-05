package admin

import (
	"context"
	"strconv"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/auditlog"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/ent/abusereport"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
)

const (
	auditUserCondition  = "audit_user"
	auditActionConition = "audit_action"
)

type (
	// AuditListService lists site-wide audit logs.
	AuditListService struct {
		Page          int            `form:"page" binding:"min=1"`
		PageSize      int            `form:"page_size" binding:"min=10,max=100"`
		OrderBy       string         `form:"order_by"`
		OrderDirection string        `form:"order_direction"`
		Conditions    map[string]string `form:"conditions"`
	}
	AuditListParamCtx struct{}

	AuditLogItem struct {
		ID        int    `json:"id"`
		UserID    int    `json:"user_id"`
		UserHash  string `json:"user_hash"`
		UserEmail string `json:"user_email"`
		Action    string `json:"action"`
		ObjType   string `json:"object_type"`
		ObjName   string `json:"object_name"`
		Detail    string `json:"detail"`
		IP        string `json:"ip"`
		CreatedAt string `json:"created_at"`
	}

	AuditListResponse struct {
		Pagination *inventory.PaginationResults `json:"pagination"`
		Logs       []AuditLogItem               `json:"logs"`
	}
)

// List returns paginated audit logs.
func (service *AuditListService) List(c *gin.Context) (*AuditListResponse, error) {
	dep := dependency.FromContext(c)
	hasher := dep.HashIDEncoder()
	db := dep.DBClient()

	query := db.AuditLog.Query()

	if uid := service.Conditions[auditUserCondition]; uid != "" {
		if parsed, err := strconv.Atoi(uid); err == nil {
			query = query.Where(auditlog.UserIDEQ(parsed))
		} else if decoded, derr := hasher.Decode(uid, hashid.UserID); derr == nil {
			query = query.Where(auditlog.UserIDEQ(decoded))
		}
	}
	if action := service.Conditions[auditActionConition]; action != "" {
		query = query.Where(auditlog.ActionEQ(action))
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

	total, err := query.Clone().Count(c)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "failed to count audit logs", err)
	}

	logs, err := query.Limit(service.PageSize).Offset((service.Page - 1) * service.PageSize).All(c)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "failed to list audit logs", err)
	}

	items := make([]AuditLogItem, 0, len(logs))
	for _, l := range logs {
		items = append(items, AuditLogItem{
			ID:        l.ID,
			UserID:    l.UserID,
			UserHash:  hashid.EncodeUserID(hasher, l.UserID),
			UserEmail: l.UserEmail,
			Action:    l.Action,
			ObjType:   l.ObjectType,
			ObjName:   l.ObjectName,
			Detail:    l.Detail,
			IP:        l.IP,
			CreatedAt: l.CreatedAt.Format("2006-01-02 15:04:05"),
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

type (
	// AbuseListService lists abuse reports.
	AbuseListService struct {
		Page          int            `form:"page" binding:"min=1"`
		PageSize      int            `form:"page_size" binding:"min=10,max=100"`
		Conditions    map[string]string `form:"conditions"`
	}
	AbuseListParamCtx struct{}

	AbuseReportItem struct {
		ID            int    `json:"id"`
		ShareID       int    `json:"share_id"`
		ShareHash     string `json:"share_hash"`
		ShareURL      string `json:"share_url"`
		ReporterEmail string `json:"reporter_email"`
		IP            string `json:"ip"`
		Reason        string `json:"reason"`
		Status        string `json:"status"`
		Note          string `json:"note"`
		CreatedAt     string `json:"created_at"`
	}

	AbuseListResponse struct {
		Pagination *inventory.PaginationResults `json:"pagination"`
		Reports    []AbuseReportItem            `json:"reports"`
	}

	// AbuseHandleService updates a report's status / note. ID is bound from
	// the URI, status/note from the JSON body (separate context keys).
	AbuseHandleService struct {
		ID     int `uri:"id" binding:"required"`
	}
	AbuseHandleParamCtx struct{}

	AbuseHandleBodyService struct {
		Status string `json:"status" binding:"omitempty,eq=pending|eq=resolved|eq=dismissed"`
		Note   string `json:"note"`
	}
	AbuseHandleBodyParamCtx struct{}

	// AbuseDeleteService batch deletes reports.
	AbuseDeleteService struct {
		ID []uint `json:"id" binding:"min=1"`
	}
	AbuseDeleteParamCtx struct{}
)

// List returns paginated abuse reports.
func (service *AbuseListService) List(c *gin.Context) (*AbuseListResponse, error) {
	dep := dependency.FromContext(c)
	hasher := dep.HashIDEncoder()
	db := dep.DBClient()

	query := db.AbuseReport.Query()
	if status := service.Conditions["status"]; status != "" {
		query = query.Where(abusereport.StatusEQ(status))
	}

	total, err := query.Clone().Count(c)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "failed to count reports", err)
	}

	reports, err := query.Order(ent.Desc(abusereport.FieldCreatedAt)).
		Limit(service.PageSize).Offset((service.Page - 1) * service.PageSize).All(c)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "failed to list reports", err)
	}

	items := make([]AbuseReportItem, 0, len(reports))
	for _, r := range reports {
		items = append(items, AbuseReportItem{
			ID:            r.ID,
			ShareID:       r.ShareID,
			ShareHash:     hashid.EncodeShareID(hasher, r.ShareID),
			ShareURL:      r.ShareURL,
			ReporterEmail: r.ReporterEmail,
			IP:            r.IP,
			Reason:        r.Reason,
			Status:        r.Status,
			Note:          r.Note,
			CreatedAt:     r.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}

	return &AbuseListResponse{
		Pagination: &inventory.PaginationResults{
			TotalItems: total,
			Page:       service.Page - 1,
			PageSize:   service.PageSize,
		},
		Reports: items,
	}, nil
}

// Handle updates a report's status/note.
func (service *AbuseHandleService) Handle(c *gin.Context, body *AbuseHandleBodyService) error {
	dep := dependency.FromContext(c)
	db := dep.DBClient()

	upd := db.AbuseReport.UpdateOneID(service.ID)
	if body != nil {
		if body.Status != "" {
			upd = upd.SetStatus(body.Status)
		}
		if body.Note != "" {
			upd = upd.SetNote(body.Note)
		}
	}
	if _, err := upd.Save(c); err != nil {
		return serializer.NewError(serializer.CodeDBError, "failed to update report", err)
	}
	return nil
}

// Delete batch deletes reports.
func (service *AbuseDeleteService) Delete(c *gin.Context) error {
	dep := dependency.FromContext(c)
	db := dep.DBClient()
	if _, err := db.AbuseReport.Delete().Where(abusereport.IDIn(loMap(service.ID)...)).Exec(c); err != nil {
		return serializer.NewError(serializer.CodeDBError, "failed to delete reports", err)
	}
	return nil
}

func loMap(ids []uint) []int {
	out := make([]int, 0, len(ids))
	for _, i := range ids {
		out = append(out, int(i))
	}
	return out
}

var _ = context.Background
