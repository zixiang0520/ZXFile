package admin

import (
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/abusereport"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
)

const abuseStatusCondition = "status"

type (
	// AbuseListService lists abuse reports.
	AbuseListService struct {
		Page       int               `json:"page" binding:"min=1"`
		PageSize   int               `json:"page_size" binding:"min=10,max=100"`
		Conditions map[string]string `json:"conditions"`
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
		ID int `uri:"id" binding:"required"`
	}
	AbuseHandleParamCtx struct{}

	AbuseHandleBodyService struct {
		Status string `json:"status" binding:"omitempty,eq=pending|eq=resolved|eq=dismissed"`
		Note   string `json:"note"`
	}
	AbuseHandleBodyParamCtx struct{}

	// AbuseDeleteService batch deletes reports.
	AbuseDeleteService struct {
		ID []uint `json:"ids" binding:"min=1"`
	}
	AbuseDeleteParamCtx struct{}
)

// List returns paginated abuse reports.
func (service *AbuseListService) List(c *gin.Context) (*AbuseListResponse, error) {
	dep := dependency.FromContext(c)
	hasher := dep.HashIDEncoder()
	db := dep.DBClient()

	query := db.AbuseReport.Query()
	if status := service.Conditions[abuseStatusCondition]; status != "" {
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
	ids := make([]int, 0, len(service.ID))
	for _, i := range service.ID {
		ids = append(ids, int(i))
	}
	if _, err := db.AbuseReport.Delete().Where(abusereport.IDIn(ids...)).Exec(c); err != nil {
		return serializer.NewError(serializer.CodeDBError, "failed to delete reports", err)
	}
	return nil
}
