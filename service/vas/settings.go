// Package vas implements the value-added service (VAS) system: shop SKUs,
// payments, points and gift codes. Feature-parity with Cloudreve Pro's
// payment system, reimplemented on the community edition.
package vas

import (
	"context"
	"encoding/json"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/gin-gonic/gin"
)

const (
	SettingSKUKey      = "vas_skus"
	SettingProviderKey = "vas_providers"

	ProductTypePoints  = "points"
	ProductTypeStorage = "storage"
	ProductTypeGroup   = "group"

	ChannelEpay   = "epay"
	ChannelCustom = "custom"
	ChannelStripe = "stripe"
	ChannelPoints = "points"

	PaymentStatusUnpaid        = "unpaid"
	PaymentStatusPaid          = "paid"
	PaymentStatusFulfilled     = "fulfilled"
	PaymentStatusFulfillFailed = "fulfill_failed"
)

// SKU is a purchasable product definition, stored as a settings JSON list.
type SKU struct {
	ID          string `json:"id"`
	Type        string `json:"type"` // points | storage | group
	Name        string `json:"name"`
	Price       int64  `json:"price"`       // in cents, 0 = points-only
	Currency    string `json:"currency,omitempty"`
	PointsPrice int64  `json:"points_price,omitempty"` // price in points
	Num         int64  `json:"num"`                    // points amount / storage bytes / group id
	OnSale      bool   `json:"on_sale"`
}

// Provider is a payment channel configuration, stored as a settings JSON list.
type Provider struct {
	ID     string            `json:"id"`
	Type   string            `json:"type"` // epay | custom | stripe
	Name   string            `json:"name"`
	OnSale bool              `json:"on_sale"`
	Config map[string]string `json:"config"`
}

// GetSKUs loads the SKU list from settings.
func GetSKUs(ctx context.Context, db *ent.Client) []SKU {
	res := make([]SKU, 0)
	raw := getSettingJSON(ctx, db, SettingSKUKey)
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &res)
	}
	return res
}

// SaveSKUs persists the SKU list.
func SaveSKUs(ctx context.Context, db *ent.Client, skus []SKU) error {
	buf, _ := json.Marshal(skus)
	return putSettingJSON(ctx, db, SettingSKUKey, string(buf))
}

// GetProviders loads the payment provider list from settings.
func GetProviders(ctx context.Context, db *ent.Client) []Provider {
	res := make([]Provider, 0)
	raw := getSettingJSON(ctx, db, SettingProviderKey)
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &res)
	}
	return res
}

// SaveProviders persists the payment provider list.
func SaveProviders(ctx context.Context, db *ent.Client, providers []Provider) error {
	buf, _ := json.Marshal(providers)
	return putSettingJSON(ctx, db, SettingProviderKey, string(buf))
}

// GetProviderByID finds one provider by ID.
func GetProviderByID(ctx context.Context, db *ent.Client, id string) (Provider, bool) {
	for _, p := range GetProviders(ctx, db) {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

// GetSKUByID finds one SKU by ID.
func GetSKUByID(ctx context.Context, db *ent.Client, id string) (SKU, bool) {
	for _, s := range GetSKUs(ctx, db) {
		if s.ID == id {
			return s, true
		}
	}
	return SKU{}, false
}

func getSettingJSON(ctx context.Context, db *ent.Client, key string) string {
	s, err := db.Setting.Query().Where(setting.NameEQ(key)).First(ctx)
	if err != nil {
		return ""
	}
	return s.Value
}

func putSettingJSON(ctx context.Context, db *ent.Client, key, value string) error {
	s, err := db.Setting.Query().Where(setting.NameEQ(key)).First(ctx)
	if err == nil {
		return db.Setting.UpdateOneID(s.ID).SetValue(value).Exec(ctx)
	}
	_, err = db.Setting.Create().SetName(key).SetValue(value).Save(ctx)
	return err
}

type (
	// SaveSKUsService persists the SKU list.
	SaveSKUsService struct {
		SKUs []SKU `json:"skus" binding:"required"`
	}
	SaveSKUsParamCtx struct{}

	// SaveProvidersService persists the provider list.
	SaveProvidersService struct {
		Providers []Provider `json:"providers" binding:"required"`
	}
	SaveProvidersParamCtx struct{}
)

// Save saves the SKU list.
func (service *SaveSKUsService) Save(c *gin.Context) error {
	db := dependency.FromContext(c).DBClient()
	return SaveSKUs(c, db, service.SKUs)
}

// Save saves the provider list.
func (service *SaveProvidersService) Save(c *gin.Context) error {
	db := dependency.FromContext(c).DBClient()
	return SaveProviders(c, db, service.Providers)
}

// ListSKUs returns the SKU list.
func ListSKUs(c *gin.Context) serializer.Response {
	db := dependency.FromContext(c).DBClient()
	return serializer.Response{Data: GetSKUs(c, db)}
}

// ListProviders returns the provider list.
func ListProviders(c *gin.Context) serializer.Response {
	db := dependency.FromContext(c).DBClient()
	return serializer.Response{Data: GetProviders(c, db)}
}
