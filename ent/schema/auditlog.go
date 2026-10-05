package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// AuditLog holds the schema definition for the AuditLog entity.
// Site-wide operation audit records (Pro "Events" feature reimplemented).
type AuditLog struct {
	ent.Schema
}

// Fields of the AuditLog.
func (AuditLog) Fields() []ent.Field {
	return []ent.Field{
		field.Int("user_id").Optional(),
		field.String("user_email").Optional().MaxLen(255),
		field.String("action").MaxLen(64),
		field.String("object_type").Optional().MaxLen(32),
		field.String("object_name").Optional().MaxLen(1024),
		field.String("detail").Optional(),
		field.String("ip").Optional().MaxLen(64),
	}
}

// Edges of the AuditLog.
func (AuditLog) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("auditlogs").
			Field("user_id").
			Unique(),
	}
}

// Indexes of the AuditLog.
func (AuditLog) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("created_at"),
		index.Fields("user_id", "created_at"),
		index.Fields("action"),
	}
}

// Mixin of the AuditLog.
func (AuditLog) Mixin() []ent.Mixin {
	return []ent.Mixin{
		CommonMixin{},
	}
}
