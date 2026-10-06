package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Payment holds the schema definition for the Payment entity.
// A payment represents one purchase order created by a user.
type Payment struct {
	ent.Schema
}

// Fields of the Payment.
func (Payment) Fields() []ent.Field {
	return []ent.Field{
		field.String("order_no").Unique().MaxLen(128),
		field.Int("user_id").Optional(),
		// Product snapshot at purchase time.
		field.String("product_type").MaxLen(32), // points | storage | group
		field.Int("sku_id").Optional(),
		field.String("sku_name").Optional().MaxLen(255),
		field.Int64("num").Optional(),     // points amount / storage bytes / group id
		field.Int("quantity").Default(1),  // purchase quantity
		field.Int64("amount").Default(0),  // price in cents
		field.String("currency").Optional().MaxLen(16),
		field.Int64("points_used").Default(0), // points deducted towards this order
		// Payment channel.
		field.String("channel").Optional().MaxLen(32), // epay | stripe | custom | points
		field.String("channel_trade_no").Optional().MaxLen(128),
		field.String("pay_url").Optional().MaxLen(2048),
		// State machine: unpaid -> paid -> fulfilled | fulfill_failed
		field.String("status").Default("unpaid").MaxLen(32),
		field.String("failure_reason").Optional().MaxLen(1024),
		// Anonymous purchase (email for receipt / resume ticket).
		field.String("email").Optional().MaxLen(255),
		field.String("resume_ticket").Optional().MaxLen(64),
	}
}

// Edges of the Payment.
func (Payment) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("payments").
			Field("user_id").
			Unique(),
	}
}

// Indexes of the Payment.
func (Payment) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "created_at"),
		index.Fields("status"),
		index.Fields("channel"),
	}
}

// Mixin of the Payment.
func (Payment) Mixin() []ent.Mixin {
	return []ent.Mixin{
		CommonMixin{},
	}
}
