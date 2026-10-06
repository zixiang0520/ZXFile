package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("email").
			MaxLen(100).
			Unique(),
		field.String("nick").
			MaxLen(100),
		field.String("password").
			Optional().
			Sensitive(),
		field.Enum("status").
			Values("active", "inactive", "manual_banned", "sys_banned").
			Default("active"),
		field.Int64("storage").
			Default(0),
		field.String("two_factor_secret").
			Sensitive().
			Optional(),
		field.String("avatar").
			Optional(),
		field.JSON("settings", &types.UserSetting{}).
			Default(&types.UserSetting{}).
			Optional(),
		field.Int("group_users"),
		// 换组回退：购买用户组商品前的原始用户组 + 到期时间（nil = 永久/未在会员组）
		field.Int("previous_group").
			Optional(),
		field.Time("group_expires").
			Optional(),
	}
}

func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("group", Group.Type).
			Ref("users").
			Field("group_users").
			Unique().
			Required(),
		edge.To("files", File.Type),
		edge.To("dav_accounts", DavAccount.Type),
		edge.To("shares", Share.Type),
		edge.To("passkey", Passkey.Type),
		edge.To("tasks", Task.Type),
		edge.To("fsevents", FsEvent.Type),
		edge.To("auditlogs", AuditLog.Type),
		edge.To("payments", Payment.Type),
		edge.To("points_ledgers", PointsLedger.Type),
		edge.To("giftcodes", GiftCode.Type),
		edge.To("entities", Entity.Type),
		edge.To("oauth_grants", OAuthGrant.Type),
	}
}

func (User) Mixin() []ent.Mixin {
	return []ent.Mixin{
		CommonMixin{},
	}
}
