package vas

// 换组到期回退：会员商品（group SKU 带 duration_days）到期后自动回退到原始用户组。
// - 履约时记录 previous_group + group_expires（fulfillGroup）
// - 定时任务扫描过期会员并回退（CronRevertExpiredGroups）

import (
	"context"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/group"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/pkg/crontab"
	"github.com/cloudreve/Cloudreve/v4/pkg/eventtype"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	"github.com/gin-gonic/gin"
)

func init() {
	crontab.Register(setting.CronTypeGroupExpire, CronRevertExpiredGroups)
}

// fulfillGroup applies the purchased group to the owner. With a duration
// snapshot (DurationDays > 0) the original group is remembered and the
// membership expires; without it the change is permanent.
func fulfillGroup(c *gin.Context, db *ent.Client, u *ent.User, p *ent.Payment) error {
	target := int(p.Num)
	upd := db.User.UpdateOneID(u.ID).SetGroupUsers(target)
	if p.DurationDays > 0 {
		// 原始组语义：已有原始组（且不是目标组本身）→ 保留最初的原始组；
		// 首次购买 → 记录当前组。到期的原始组不存在时由回退任务兜底到默认组。
		prev := u.PreviousGroup
		if prev == 0 || prev == target {
			prev = u.GroupUsers
		}
		if prev != target {
			upd = upd.SetPreviousGroup(prev).SetGroupExpires(time.Now().Add(time.Duration(p.DurationDays) * 24 * time.Hour))
		}
	} else {
		upd = upd.ClearPreviousGroup().ClearGroupExpires()
	}
	if _, err := upd.Save(c); err != nil {
		return err
	}
	writeAuditEvent(c, db, u.ID, u.Email, eventtype.GroupChanged, "user", u.Email, map[string]interface{}{
		"group_to":       target,
		"duration_days":  p.DurationDays,
		"previous_group": u.PreviousGroup,
	})
	return nil
}

// CronRevertExpiredGroups 到期回退：把会员组已过期的用户回退到原始用户组；
// 原始组已删除时回退到站点默认组。
func CronRevertExpiredGroups(ctx context.Context) {
	dep := dependency.FromContext(ctx)
	db := dep.DBClient()
	l := dep.Logger()

	users, err := db.User.Query().
		Where(
			user.PreviousGroupNotNil(),
			user.PreviousGroupGT(0),
			user.GroupExpiresNotNil(),
			user.GroupExpiresLT(time.Now()),
		).
		All(ctx)
	if err != nil {
		l.Error("group expire: failed to query expired memberships: %s", err)
		return
	}

	for _, u := range users {
		prev := u.PreviousGroup
		if prev == u.GroupUsers {
			// 已在原始组（手动改过）：只清标记
			if err := db.User.UpdateOneID(u.ID).ClearPreviousGroup().ClearGroupExpires().Exec(ctx); err != nil {
				l.Error("group expire: failed to clear #%d: %s", u.ID, err)
			}
			continue
		}
		// 原始组已被删除 → 回退到站点默认组
		if _, err := db.Group.Query().Where(group.IDEQ(prev)).First(ctx); err != nil {
			def := dep.SettingProvider().DefaultGroup(ctx)
			l.Warning("group expire: previous group %d gone for #%d, fallback to default group %d", prev, u.ID, def)
			prev = def
		}
		if err := db.User.UpdateOneID(u.ID).
			SetGroupUsers(prev).
			ClearPreviousGroup().
			ClearGroupExpires().
			Exec(ctx); err != nil {
			l.Error("group expire: failed to revert #%d: %s", u.ID, err)
			continue
		}
		writeAuditEvent(ctx, db, u.ID, u.Email, eventtype.GroupChanged, "user", u.Email, map[string]interface{}{
			"group_from": u.GroupUsers,
			"group_to":   prev,
			"reason":     "membership_expired",
		})
		l.Info("group expire: user #%d reverted %d -> %d", u.ID, u.GroupUsers, prev)
	}
}

// writeAuditEvent 统一写审计事件（auditWriter 的导出别名，供本包各文件使用）
func writeAuditEvent(ctx context.Context, db *ent.Client, userID int, email string,
	ev eventtype.EventType, objType, objName string, content map[string]interface{}) {
	auditWriter(ctx, db, userID, email, ev, objType, objName, content)
}
