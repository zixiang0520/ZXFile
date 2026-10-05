package explorer

import (
	"context"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/gin-gonic/gin"
)

// WriteAudit records a user operation into the site-wide audit log
// (best-effort, async - never blocks the main operation).
func WriteAudit(c *gin.Context, action, objType, objName, detail string) {
	dep := dependency.FromContext(c)
	if dep == nil {
		return
	}
	user := inventory.UserFromContext(c)
	db := dep.DBClient()
	l := logging.FromContext(c)

	userID, userEmail := 0, ""
	if user != nil {
		userID, userEmail = user.ID, user.Email
	}
	ip := c.ClientIP()
	objectName := objName

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		creator := db.AuditLog.Create().
			SetAction(action).
			SetObjectType(objType).
			SetObjectName(objectName).
			SetDetail(detail).
			SetIP(ip)
		if userID > 0 {
			creator = creator.SetUserID(userID).SetUserEmail(userEmail)
		}
		if _, err := creator.Save(ctx); err != nil {
			l.Warning("Failed to write audit log (action=%s): %s", action, err)
		}
	}()
}
