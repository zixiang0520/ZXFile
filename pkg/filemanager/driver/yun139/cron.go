package yun139

// 定时刷新所有移动云盘策略的 Authorization（自动续期）：
//   - 剩余 > 15 天 → 跳过
//   - authTokenRefresh.do 续期；失败且有邮箱 Cookie + 用户名 + 密码 → 密码登录
//   - 新 token 持久化到策略 AccessKey（并清除缓存）

import (
	"context"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/crontab"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
)

func init() {
	crontab.Register(setting.CronTypeYun139TokenRefresh, CronRefreshTokens)
}

// CronRefreshTokens 定时续期所有 yun139 策略 Token
func CronRefreshTokens(ctx context.Context) {
	dep := dependency.FromContext(ctx)
	client := dep.StoragePolicyClient()
	if client == nil {
		return
	}
	policies, err := client.ListPolicyByType(ctx, types.PolicyTypeYun139)
	if err != nil {
		dep.Logger().Warning("yun139 token refresh: failed to list policies: %s", err)
		return
	}
	for _, p := range policies {
		info := policyInfoFrom(p)
		if info.Authorization == "" && (info.Username == "" || info.Password == "" || info.MailCookies == "") {
			continue
		}
		newAuth, source, err := RenewToken(ctx, info)
		if err != nil {
			dep.Logger().Warning("yun139 token refresh failed for policy #%d: %s", p.ID, err)
			continue
		}
		if source != "keep" && newAuth != "" && newAuth != p.AccessKey {
			updated := *p
			updated.AccessKey = newAuth
			if err := client.UpdateAccessKey(ctx, &updated, newAuth); err != nil {
				dep.Logger().Warning("yun139 token refresh: persist failed for policy #%d: %s", p.ID, err)
				continue
			}
			dep.Logger().Info("yun139 token refreshed for policy #%d (%s)", p.ID, source)
		}
	}
}
