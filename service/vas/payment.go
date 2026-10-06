package vas

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/payment"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/eventtype"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
)

// CreatePaymentParamCtx defines the context key.
type CreatePaymentParamCtx struct{}

// CreatePaymentRequest is the payload for creating a purchase order.
type CreatePaymentRequest struct {
	SKUID      string `json:"sku_id"`
	Type       string `json:"type"`  // points recharge without SKU
	Num        int64  `json:"num"`   // points recharge amount
	Quantity   int    `json:"qyt"`   // quantity
	ProviderID string `json:"provider_id"`
	UsePoints  bool   `json:"use_points"`
	Email      string `json:"email"` // anonymous purchase receipt
}

// PaymentResponse is returned after order creation / status polling.
type PaymentResponse struct {
	OrderNo  string `json:"order_no"`
	Status   string `json:"status"`
	PayURL   string `json:"pay_url,omitempty"`
	Amount   int64  `json:"amount"`
	Currency string `json:"currency,omitempty"`
}

// Create creates an order and returns the cashier URL.
func (service *CreatePaymentRequest) Create(c *gin.Context) serializer.Response {
	dep := dependency.FromContext(c)
	db := dep.DBClient()
	user := currentUser(c)

	var req CreatePaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return serializer.ParamErr(c, "Invalid payment request", err)
	}
	if req.Quantity < 1 {
		req.Quantity = 1
	}

	var (
		sku        SKU
		totalCost  int64
		pointsCost int64
		currency   = "CNY"
		name       string
		num        int64
		ptype      string
	)
	if req.SKUID != "" {
		var ok bool
		sku, ok = GetSKUByID(c, db, req.SKUID)
		if !ok || !sku.OnSale {
			return serializer.Err(c, serializer.NewError(serializer.CodeNotFound, "Product not found or not on sale", nil))
		}
		ptype, name, num = sku.Type, sku.Name, sku.Num
		if sku.Currency != "" {
			currency = sku.Currency
		}
		totalCost = sku.Price * int64(req.Quantity)
		pointsCost = sku.PointsPrice * int64(req.Quantity)
	} else if req.Type == ProductTypePoints && req.Num > 0 {
		// Points recharge without a SKU: default rate 1 cent per point.
		ptype, num = ProductTypePoints, req.Num
		totalCost = req.Num
		name = fmt.Sprintf("%d 积分", req.Num)
	} else {
		return serializer.Err(c, serializer.NewError(serializer.CodeParamErr, "Invalid product", nil))
	}

	// Points payment: the SKU's points price fully covers the order.
	usePoints := req.UsePoints && pointsCost > 0 && user != nil
	if usePoints && GetPointsBalance(c, db, user.ID) < pointsCost {
		return serializer.Err(c, serializer.NewError(serializer.CodeNoPermissionErr, "积分余额不足", nil))
	}

	orderNo := genOrderNo()
	resumeTicket := genResumeTicket()

	create := db.Payment.Create().
		SetOrderNo(orderNo).
		SetProductType(ptype).
		SetSkuName(name).
		SetNum(num).
		SetQuantity(req.Quantity).
		SetAmount(totalCost).
		SetCurrency(currency).
		SetStatus(PaymentStatusUnpaid).
		SetResumeTicket(resumeTicket)
	if user != nil {
		create = create.SetUserID(user.ID)
	}
	if req.Email != "" {
		create = create.SetEmail(req.Email)
	}
	p, err := create.Save(c)
	if err != nil {
		return serializer.DBErr(c, "Failed to create payment", err)
	}

	// Pure points payment: fulfill immediately.
	if usePoints {
		if _, err := DeductPoints(c, db, user.ID, pointsCost, "purchase", name, p.ID); err != nil {
			return serializer.Err(c, serializer.NewError(serializer.CodeDBError, "积分扣除失败", err))
		}
		_ = db.Payment.UpdateOneID(p.ID).SetPointsUsed(pointsCost).SetChannel(ChannelPoints).Exec(c)
		if err := fulfillOrder(c, db, user, p); err != nil {
			_ = markFulfillFailed(c, db, p, err.Error())
			return serializer.Err(c, serializer.NewError(serializer.CodeDBError, "订单履行失败", err))
		}
		writePaymentEvent(c, db, eventtype.PaymentCreated, p)
		writePaymentEvent(c, db, eventtype.PaymentPaid, p)
		writePaymentEvent(c, db, eventtype.PaymentFulfilled, p)
		return serializer.Response{Data: PaymentResponse{OrderNo: orderNo, Status: PaymentStatusFulfilled}}
	}

	// Cash channel.
	provider, ok := GetProviderByID(c, db, req.ProviderID)
	if !ok || !provider.OnSale {
		_ = db.Payment.DeleteOneID(p.ID).Exec(c)
		return serializer.Err(c, serializer.NewError(serializer.CodeNotFound, "Payment channel not available", nil))
	}

	var payURL string
	switch provider.Type {
	case ChannelEpay:
		payURL, err = epayCreate(c, provider, p)
	case ChannelCustom:
		payURL, err = customCreate(c, provider, p)
	case ChannelStripe:
		return serializer.Err(c, serializer.NewError(serializer.CodeInternalSetting, "Stripe 渠道暂未实现，请使用易支付或自定义网关", nil))
	default:
		return serializer.Err(c, serializer.NewError(serializer.CodeParamErr, "Unknown provider type", nil))
	}
	if err != nil {
		_ = db.Payment.DeleteOneID(p.ID).Exec(c)
		return serializer.Err(c, serializer.NewError(serializer.CodeInternalSetting, "Failed to create payment: "+err.Error(), err))
	}

	_ = db.Payment.UpdateOneID(p.ID).SetPayURL(payURL).SetChannel(provider.Type).Exec(c)
	writePaymentEvent(c, db, eventtype.PaymentCreated, p)

	return serializer.Response{Data: PaymentResponse{
		OrderNo: orderNo, Status: PaymentStatusUnpaid, PayURL: payURL,
		Amount: totalCost, Currency: currency,
	}}
}

// PaymentStatus polls an order's status. Anonymous callers must present a
// valid resume ticket.
func PaymentStatus(c *gin.Context) serializer.Response {
	dep := dependency.FromContext(c)
	db := dep.DBClient()
	user := currentUser(c)

	orderNo := c.Param("order")
	if orderNo == "" {
		orderNo = c.Query("order_no")
	}
	channel := c.Param("channel")
	if channel == "" {
		channel = c.Query("channel")
	}
	p, err := db.Payment.Query().Where(payment.OrderNoEQ(orderNo)).First(c)
	if err != nil {
		return serializer.Response{Code: serializer.CodeNotFound, Msg: "Not found"}
	}
	if user == nil || p.UserID != user.ID {
		if p.ResumeTicket == "" || c.Query("ticket") != p.ResumeTicket {
			return serializer.Response{Code: serializer.CodeNotFound, Msg: "Not found"}
		}
	}

	// Actively poll the channel for unpaid orders.
	if p.Status == PaymentStatusUnpaid && p.Channel != "" && p.Channel != ChannelPoints {
		_ = pollChannelStatus(c, db, p, channel)
		p, _ = db.Payment.Query().Where(payment.OrderNoEQ(orderNo)).First(c)
	}

	return serializer.Response{Data: PaymentResponse{
		OrderNo: p.OrderNo, Status: p.Status, Amount: p.Amount, Currency: p.Currency,
	}}
}

// ListMyPayments returns the current user's orders.
func ListMyPayments(c *gin.Context) serializer.Response {
	dep := dependency.FromContext(c)
	db := dep.DBClient()
	user := currentUser(c)
	if user == nil {
		return serializer.Err(c, serializer.NewError(serializer.CodeNoPermissionErr, "Login required", nil))
	}
	page, size := pageParams(c)
	ps, err := db.Payment.Query().Where(payment.UserIDEQ(user.ID)).
		Order(ent.Desc(payment.FieldCreatedAt)).
		Limit(size).Offset((page - 1) * size).All(c)
	if err != nil {
		return serializer.DBErr(c, "Failed to list payments", err)
	}
	out := lo.Map(ps, func(p *ent.Payment, _ int) map[string]interface{} { return paymentJSON(p) })
	return serializer.Response{Data: out}
}

// AdminListPayments lists all payments for the admin panel.
func AdminListPayments(c *gin.Context) serializer.Response {
	dep := dependency.FromContext(c)
	db := dep.DBClient()
	page, size := pageParams(c)
	q := db.Payment.Query().WithUser()
	if status := c.Query("status"); status != "" {
		q = q.Where(payment.StatusEQ(status))
	}
	ps, err := q.Order(ent.Desc(payment.FieldCreatedAt)).
		Limit(size).Offset((page - 1) * size).All(c)
	if err != nil {
		return serializer.DBErr(c, "Failed to list payments", err)
	}
	total, _ := q.Clone().Count(c)
	out := lo.Map(ps, func(p *ent.Payment, _ int) map[string]interface{} {
		item := paymentJSON(p)
		item["user"] = p.Edges.User
		return item
	})
	return serializer.Response{Data: map[string]interface{}{
		"payments": out,
		"pagination": map[string]interface{}{
			"total_items": total, "page": page - 1, "page_size": size,
		},
	}}
}

// AdminDeletePayments batch deletes payments.
func AdminDeletePayments(c *gin.Context) serializer.Response {
	dep := dependency.FromContext(c)
	db := dep.DBClient()
	var req struct {
		IDs []int `json:"ids" binding:"min=1"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		return serializer.ParamErr(c, "Invalid request", err)
	}
	if _, err := db.Payment.Delete().Where(payment.IDIn(req.IDs...)).Exec(c); err != nil {
		return serializer.DBErr(c, "Failed to delete payments", err)
	}
	return serializer.Response{}
}

// ─── fulfillment & state machine ─────────────────────────────

// markPaid transitions an order to paid (idempotent).
func markPaid(ctx context.Context, db *ent.Client, p *ent.Payment, tradeNo string) error {
	if p.Status != PaymentStatusUnpaid {
		return nil // already processed
	}
	upd := db.Payment.UpdateOneID(p.ID).SetStatus(PaymentStatusPaid)
	if tradeNo != "" {
		upd = upd.SetChannelTradeNo(tradeNo)
	}
	_, err := upd.Save(ctx)
	return err
}

// markFulfilled transitions an order to fulfilled.
func markFulfilled(ctx context.Context, db *ent.Client, p *ent.Payment) error {
	_, err := db.Payment.UpdateOneID(p.ID).SetStatus(PaymentStatusFulfilled).Save(ctx)
	return err
}

// markFulfillFailed transitions an order to fulfill_failed with a reason.
func markFulfillFailed(ctx context.Context, db *ent.Client, p *ent.Payment, reason string) error {
	_, err := db.Payment.UpdateOneID(p.ID).
		SetStatus(PaymentStatusFulfillFailed).
		SetFailureReason(reason).
		Save(ctx)
	return err
}

// pollChannelStatus actively queries the channel for payment status.
// epay is notify-driven (no query API); the custom gateway supports
// signed GET /order queries.
func pollChannelStatus(c *gin.Context, db *ent.Client, p *ent.Payment, channel string) bool {
	if channel == ChannelCustom {
		provider, ok := GetProviderByID(c, db, p.Channel)
		if !ok {
			return false
		}
		return pollCustom(c, db, provider, p)
	}
	return false
}

// fulfillOrder applies the purchased product to the owner.
func fulfillOrder(c *gin.Context, db *ent.Client, u *ent.User, p *ent.Payment) error {
	if u == nil || u.ID == 0 {
		// Prefer the order owner recorded on the payment row.
		if p.UserID > 0 {
			var err error
			u, err = db.User.Query().Where(user.IDEQ(p.UserID)).First(c)
			if err != nil {
				return fmt.Errorf("failed to load order owner #%d: %w", p.UserID, err)
			}
		} else {
			u = currentUser(c)
			if u != nil && u.ID == 0 {
				u = nil
			}
		}
	}
	if u == nil {
		return fmt.Errorf("anonymous order cannot be fulfilled")
	}

	var err error
	switch p.ProductType {
	case ProductTypeStorage:
		err = addExtraStorage(c, db, u.ID, p.Num*int64(p.Quantity))
	case ProductTypeGroup:
		_, err = db.User.UpdateOneID(u.ID).SetGroupUsers(int(p.Num)).Save(c)
	case ProductTypePoints:
		_, err = GainPoints(c, db, u.ID, p.Num*int64(p.Quantity), "recharge", p.OrderNo, p.ID)
	default:
		err = fmt.Errorf("unknown product type %q", p.ProductType)
	}
	if err != nil {
		return err
	}
	writePaymentEvent(c, db, eventtype.PaymentFulfilled, p)
	return markFulfilled(c, db, p)
}

// handleNotify processes a verified payment notification: mark paid then
// fulfill the order (idempotent at every step).
func handleNotify(c *gin.Context, db *ent.Client, p *ent.Payment, tradeNo string) {
	if err := markPaid(c, db, p, tradeNo); err != nil {
		return
	}
	writePaymentEvent(c, db, eventtype.PaymentPaid, p)
	if err := fulfillOrder(c, db, nil, p); err != nil {
		_ = markFulfillFailed(c, db, p, err.Error())
		writePaymentEvent(c, db, eventtype.PaymentFulfillFailed, p)
	}
}

// ─── helpers ─────────────────────────────────────────────────

func currentUser(c *gin.Context) *ent.User {
	return inventory.UserFromContext(c)
}

func pageParams(c *gin.Context) (int, int) {
	page, _ := strconv.Atoi(c.Query("page"))
	if page < 1 {
		page = 1
	}
	size, _ := strconv.Atoi(c.Query("page_size"))
	if size < 10 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	return page, size
}

func genOrderNo() string {
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	return fmt.Sprintf("ZX%s%s", time.Now().Format("20060102150405"), hex.EncodeToString(buf))
}

func genResumeTicket() string {
	buf := make([]byte, 24)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func paymentJSON(p *ent.Payment) map[string]interface{} {
	return map[string]interface{}{
		"id": p.ID, "order_no": p.OrderNo, "product_type": p.ProductType,
		"sku_name": p.SkuName, "num": p.Num, "quantity": p.Quantity,
		"amount": p.Amount, "currency": p.Currency, "points_used": p.PointsUsed,
		"channel": p.Channel, "status": p.Status, "email": p.Email,
		"created_at": p.CreatedAt.Format("2006-01-02 15:04:05"),
	}
}

// writePaymentEvent records a payment lifecycle audit event.
func writePaymentEvent(c *gin.Context, db *ent.Client, ev eventtype.EventType, p *ent.Payment) {
	auditWriter(c, db, p.UserID, p.Email, ev, "payment", p.SkuName,
		map[string]interface{}{"order_no": p.OrderNo, "amount": p.Amount, "channel": p.Channel})
}


type (
	// AdminDeletePaymentsService batch deletes payments.
	AdminDeletePaymentsService struct {
		IDs []int `json:"ids" binding:"min=1"`
	}
	AdminDeletePaymentsParamCtx struct{}
)
