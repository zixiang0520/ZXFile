package vas

import (
	"context"
	"crypto/rand"
	"fmt"
	"strconv"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/giftcode"
	"github.com/cloudreve/Cloudreve/v4/ent/pointsledger"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/eventtype"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"time"
	"github.com/gin-gonic/gin"
)

// AdminCreateGiftCodesParamCtx defines the context key.
type AdminCreateGiftCodesParamCtx struct{}

// AdminCreateGiftCodesService is the payload for batch gift code creation.
type AdminCreateGiftCodesService struct {
	Count       int    `json:"count" binding:"min=1,max=100"`
	ProductType string `json:"product_type" binding:"required,eq=points|eq=storage|eq=group"`
	Num         int64  `json:"num"`
	Name        string `json:"name"`
	Prefix      string `json:"prefix"`
}

// AdminCreateGiftCodes generates gift codes in batch.
func AdminCreateGiftCodes(c *gin.Context) serializer.Response {
	dep := dependency.FromContext(c)
	db := dep.DBClient()
	user := inventory.UserFromContext(c)

	var req struct {
		Count       int    `json:"count" binding:"min=1,max=100"`
		ProductType string `json:"product_type" binding:"required,eq=points|eq=storage|eq=group"`
		Num         int64  `json:"num"`
		Name        string `json:"name"`
		Prefix      string `json:"prefix"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		return serializer.ParamErr(c, "Invalid request", err)
	}

	created := make([]string, 0, req.Count)
	for i := 0; i < req.Count; i++ {
		code := req.Prefix + genCode(12)
		creator := db.GiftCode.Create().
			SetCode(code).
			SetProductType(req.ProductType).
			SetNum(req.Num)
		if req.Name != "" {
			creator = creator.SetName(req.Name)
		}
		if user != nil {
			creator = creator.SetCreatedByEmail(user.Email)
		}
		if _, err := creator.Save(c); err != nil {
			continue
		}
		created = append(created, code)
	}

	return serializer.Response{Data: map[string]interface{}{
		"codes": created,
		"count": len(created),
	}}
}

// AdminListGiftCodes lists gift codes.
func AdminListGiftCodes(c *gin.Context) serializer.Response {
	dep := dependency.FromContext(c)
	db := dep.DBClient()
	page, size := pageParams(c)

	q := db.GiftCode.Query()
	if used := c.Query("used"); used == "true" || used == "false" {
		q = q.Where(giftcode.UsedEQ(used == "true"))
	}
	total, _ := q.Clone().Count(c)
	codes, err := q.Order(ent.Desc(giftcode.FieldCreatedAt)).
		Limit(size).Offset((page - 1) * size).All(c)
	if err != nil {
		return serializer.DBErr(c, "Failed to list gift codes", err)
	}
	return serializer.Response{Data: map[string]interface{}{
		"gift_codes": codes,
		"pagination": map[string]interface{}{"total_items": total, "page": page - 1, "page_size": size},
	}}
}

// AdminDeleteGiftCodesParamCtx defines the context key.
type AdminDeleteGiftCodesParamCtx struct{}

// AdminDeleteGiftCodesService is the payload for batch deletion.
type AdminDeleteGiftCodesService struct {
	IDs []int `json:"ids" binding:"min=1"`
}

// AdminDeleteGiftCodes batch deletes gift codes.
func AdminDeleteGiftCodes(c *gin.Context) serializer.Response {
	dep := dependency.FromContext(c)
	db := dep.DBClient()
	var req struct {
		IDs []int `json:"ids" binding:"min=1"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		return serializer.ParamErr(c, "Invalid request", err)
	}
	if _, err := db.GiftCode.Delete().Where(giftcode.IDIn(req.IDs...)).Exec(c); err != nil {
		return serializer.DBErr(c, "Failed to delete gift codes", err)
	}
	return serializer.Response{}
}

// Redeem redeems a gift code for the current user.
func Redeem(c *gin.Context) serializer.Response {
	dep := dependency.FromContext(c)
	db := dep.DBClient()
	user := inventory.UserFromContext(c)
	if user == nil {
		return serializer.Err(c, serializer.NewError(serializer.CodeNoPermissionErr, "Login required", nil))
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		return serializer.ParamErr(c, "Invalid request", err)
	}

	code, err := db.GiftCode.Query().Where(giftcode.CodeEQ(req.Code)).First(c)
	if err != nil {
		return serializer.Err(c, serializer.NewError(serializer.CodeNotFound, "兑换码不存在", err))
	}
	if code.Used {
		return serializer.Err(c, serializer.NewError(serializer.CodeParamErr, "兑换码已被使用", nil))
	}

	// Fulfill + mark used in one transaction.
	tx, txErr := db.Tx(c)
	if txErr != nil {
		return serializer.DBErr(c, "Failed to start transaction", txErr)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.GiftCode.UpdateOneID(code.ID).
		SetUsed(true).
		SetUsedBy(user.ID).
		SetUsedByEmail(user.Email).
		Save(c); err != nil {
		return serializer.DBErr(c, "Failed to redeem", err)
	}

	switch code.ProductType {
	case ProductTypePoints:
		if _, err := GainPointsTx(c, tx, user.ID, code.Num, "redeem", code.Code); err != nil {
			return serializer.DBErr(c, "Failed to add points", err)
		}
	case ProductTypeStorage:
		if err := addExtraStorage(c, tx.Client(), user.ID, code.Num); err != nil {
			return serializer.DBErr(c, "Failed to add storage", err)
		}
	case ProductTypeGroup:
		if _, err := tx.User.UpdateOneID(user.ID).SetGroupUsers(int(code.Num)).Save(c); err != nil {
			return serializer.DBErr(c, "Failed to change group", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return serializer.DBErr(c, "Failed to commit redemption", err)
	}
	committed = true

	auditWriter(c, db, user.ID, user.Email, eventtype.RedeemGiftCode, code.ProductType,
		code.Name, map[string]interface{}{"code": code.Code, "num": code.Num})

	var reward int64 = code.Num
	if code.ProductType == ProductTypePoints {
		reward = code.Num
	}
	return serializer.Response{Data: map[string]interface{}{
		"product_type": code.ProductType,
		"num":          reward,
		"name":         code.Name,
	}}
}

// genCode generates a random alphanumeric code.
func genCode(length int) string {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, 0, length)
	for _, b := range buf {
		out = append(out, charset[int(b)%len(charset)])
	}
	return string(out)
}

// GiftCodeRewards exposes reward resolution for gift code redemption API.
func GiftCodeRewards(c *gin.Context, code string) (string, string, int64, bool) {
	dep := dependency.FromContext(c)
	db := dep.DBClient()
	gc, err := db.GiftCode.Query().Where(giftcode.CodeEQ(code)).First(c)
	if err != nil {
		return "", "", 0, false
	}
	return gc.ProductType, gc.Name, gc.Num, !gc.Used
}

var _ = context.Background()
var _ = strconv.Itoa
var _ = fmt.Sprintf

type (
	// RedeemService redeems a gift code for the current user.
	RedeemService struct {
		Code string `json:"code" binding:"required"`
	}
	RedeemParamCtx struct{}
)

// PointsSummary returns the user's points balance + recent history.
func PointsSummary(c *gin.Context) serializer.Response {
	dep := dependency.FromContext(c)
	db := dep.DBClient()
	user := inventory.UserFromContext(c)
	if user == nil {
		return serializer.Err(c, serializer.NewError(serializer.CodeNoPermissionErr, "Login required", nil))
	}
	balance := GetPointsBalance(c, db, user.ID)
	history, err := db.PointsLedger.Query().
		Where(pointsledger.UserIDEQ(user.ID)).
		Order(ent.Desc(pointsledger.FieldCreatedAt)).
		Limit(50).
		All(c)
	if err != nil {
		return serializer.DBErr(c, "Failed to load points history", err)
	}
	return serializer.Response{Data: map[string]interface{}{
		"balance": balance,
		"history": history,
	}}
}
