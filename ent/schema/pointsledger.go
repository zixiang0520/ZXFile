package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// PointsLedger records every points balance change for a user
// (recharge / purchase / share income / manual adjustment).
type PointsLedger struct {
	ent.Schema
}

// Fields of the PointsLedger.
func (PointsLedger) Fields() []ent.Field {
	return []ent.Field{
		field.Int("user_id").Optional(),
		field.Int64("delta"), // positive = gain, negative = spend
		field.Int64("balance_after"),
		field.String("reason").MaxLen(64), // recharge | share_gain | share_pay | purchase | manual
		field.String("note").Optional().MaxLen(512),
		field.Int("payment_id").Optional(),
	}
}

// Edges of the PointsLedger.
func (PointsLedger) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("points_ledgers").
			Field("user_id").
			Unique(),
		edge.To("payment", Payment.Type).
			Field("payment_id").
			Unique(),
	}
}

// Indexes of the PointsLedger.
func (PointsLedger) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "created_at"),
		index.Fields("reason"),
	}
}

// Mixin of the PointsLedger.
func (PointsLedger) Mixin() []ent.Mixin {
	return []ent.Mixin{
		CommonMixin{},
	}
}
