package user

import (
	"context"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/eventtype"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
)

// WriteAuthAudit records authentication events (login / login failed) into
// the site-wide audit log. Best-effort, async.
func WriteAuthAudit(c *gin.Context, ev eventtype.EventType, email string, err error) {
	dep := dependency.FromContext(c)
	if dep == nil {
		return
	}
	db := dep.DBClient()
	l := logging.FromContext(c)

	ip := c.ClientIP()
	var userID int
	if u := inventory.UserFromContext(c); u != nil {
		userID = u.ID
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		creator := db.AuditLog.Create().
			SetType(int(ev)).
			SetAction(ev.Name()).
			SetObjectType("user").
			SetObjectName(email).
			SetContent(map[string]interface{}{
				"email": email,
				"error": errDetail(err),
			}).
			SetIP(ip)
		if userID > 0 {
			creator = creator.SetUserID(userID).SetUserEmail(email)
		}
		if _, e := creator.Save(ctx); e != nil {
			l.Warning("Failed to write auth audit (event=%s): %s", ev.Name(), e)
		}
	}()
}

func errDetail(err error) string {
	if err == nil {
		return ""
	}
	if appErr, ok := err.(*serializer.AppError); ok {
		return appErr.Msg
	}
	return err.Error()
}
