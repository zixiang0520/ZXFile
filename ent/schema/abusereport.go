package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// AbuseReport holds the schema definition of the AbuseReport entity.
// Pro "Abuse report" feature reimplemented.
type AbuseReport struct {
	ent.Schema
}

// Fields of the AbuseReport.
func (AbuseReport) Fields() []ent.Field {
	return []ent.Field{
		field.Int("share_id").Optional(),
		field.String("share_url").Optional().MaxLen(1024),
		field.String("reporter_email").Optional().MaxLen(255),
		field.String("ip").Optional().MaxLen(64),
		field.Text("reason"),
		field.String("status").Default("pending").MaxLen(32),
		field.String("note").Optional(),
	}
}

// Indexes of the AbuseReport.
func (AbuseReport) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("status"),
		index.Fields("share_id"),
		index.Fields("created_at"),
	}
}

// Mixin of the AbuseReport.
func (AbuseReport) Mixin() []ent.Mixin {
	return []ent.Mixin{
		CommonMixin{},
	}
}
