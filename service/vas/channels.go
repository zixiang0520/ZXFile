package vas

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"io"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/payment"
	"github.com/cloudreve/Cloudreve/v4/pkg/eventtype"
	"github.com/gin-gonic/gin"
)

// ─── Epay (易支付) channel ────────────────────────────────────
// Standard epay protocol: MD5 signed submit + async notify.

type epayConfig struct {
	GatewayURL string // e.g. https://pay.example.com/
	PID        string // merchant id
	Key        string // merchant key
}

func parseEpayConfig(cfg map[string]string) epayConfig {
	return epayConfig{
		GatewayURL: strings.TrimRight(cfg["gateway_url"], "/"),
		PID:        cfg["pid"],
		Key:        cfg["key"],
	}
}

func siteBaseURL(c *gin.Context) string {
	dep := dependencyFromGin(c)
	if dep == nil {
		return ""
	}
	if u := dep.SettingProvider().SiteURL(c); u != nil {
		return strings.TrimRight(u.String(), "/")
	}
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + c.Request.Host
}

// epayCreate builds the epay cashier URL for an order.
func epayCreate(c *gin.Context, provider Provider, p *ent.Payment) (string, error) {
	cfg := parseEpayConfig(provider.Config)
	if cfg.GatewayURL == "" || cfg.PID == "" || cfg.Key == "" {
		return "", fmt.Errorf("epay provider is not fully configured")
	}
	dep := dependencyFromGin(c)
	siteURL := ""
	if dep != nil {
		if u := dep.SettingProvider().SiteURL(c); u != nil {
			siteURL = strings.TrimRight(u.String(), "/")
		}
	}

	params := map[string]string{
		"pid":          cfg.PID,
		"type":         provider.Config["default_type"], // alipay / wxpay / qqpay...
		"out_trade_no": p.OrderNo,
		"notify_url":   fmt.Sprintf("%s/api/v4/payment/notify/epay/%s", siteURL, provider.ID),
		"return_url":   fmt.Sprintf("%s/vas/payment/status/%s?channel=%s&ticket=%s", siteURL, p.OrderNo, ChannelEpay, p.ResumeTicket),
		"name":         p.SkuName,
		"money":        fmt.Sprintf("%.2f", float64(p.Amount)/100),
	}
	if p.Currency != "" && strings.ToUpper(p.Currency) != "CNY" {
		// epay is CNY-native; currency mismatch must be handled by the
		// gateway operator via pricing.
		_ = p.Currency
	}

	sign := epaySign(params, cfg.Key)
	params["sign"] = sign
	params["sign_type"] = "MD5"

	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	return cfg.GatewayURL + "/submit.php?" + q.Encode(), nil
}

// epaySign computes the epay MD5 signature: ASCII-sorted params (excluding
// sign/sign_type/empty values), appended with the key.
func epaySign(params map[string]string, key string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if k == "sign" || k == "sign_type" || v == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+params[k])
	}
	raw := strings.Join(pairs, "&") + key
	return md5Sum([]byte(raw))
}

// EpayNotify processes the epay async notify (GET or POST).
func EpayNotify(c *gin.Context, providerID string) {
	dep := dependencyFromGin(c)
	db := dep.DBClient()
	provider, ok := GetProviderByID(c.Request.Context(), db, providerID)
	if !ok || provider.Type != ChannelEpay {
		c.String(400, "fail")
		return
	}
	cfg := parseEpayConfig(provider.Config)

	params := map[string]string{}
	for k, v := range c.Request.URL.Query() {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}
	_ = c.Request.ParseForm()
	for k, v := range c.Request.PostForm {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}

	if params["trade_status"] != "TRADE_SUCCESS" {
		c.String(200, "success") // not a success notification, ack and ignore
		return
	}
	computed := epaySign(params, cfg.Key)
	if computed != params["sign"] {
		dep.Logger().Debug("[EpayNotify DEBUG] sign mismatch: got=%q computed=%q params=%v", params["sign"], computed, params)
		c.String(400, "sign error")
		return
	}

	p, err := db.Payment.Query().Where(payment.OrderNoEQ(params["out_trade_no"])).First(c.Request.Context())
	if err != nil {
		dep.Logger().Debug("[EpayNotify DEBUG] order lookup failed: %v", err)
		c.String(200, "success") // unknown order, ack to stop retries
		return
	}
	dep.Logger().Debug("[EpayNotify DEBUG] order found: id=%d user_id=%d status=%s", p.ID, p.UserID, p.Status)

	handleNotify(c, db, p, params["trade_no"])
	c.String(200, "success")
}

// ─── Custom gateway channel (Pro-compatible protocol) ─────────

type customConfig struct {
	GatewayURL       string
	CommunicationKey string
}

func parseCustomConfig(cfg map[string]string) customConfig {
	return customConfig{
		GatewayURL:       strings.TrimRight(cfg["gateway_url"], "/"),
		CommunicationKey: cfg["communication_key"],
	}
}

// crSign computes the Pro custom-gateway signature:
// base64url(HMAC-SHA256(signContent, key)) where signContent = "body:path:timestamp".
func crSign(body, path, timestamp, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(body + ":" + path + ":" + timestamp))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// customCreate creates the order on the custom gateway and returns its
// cashier URL.
func customCreate(c *gin.Context, provider Provider, p *ent.Payment) (string, error) {
	cfg := parseCustomConfig(provider.Config)
	dep := dependencyFromGin(c)
	siteURL := ""
	if dep != nil {
		if u := dep.SettingProvider().SiteURL(c); u != nil {
			siteURL = strings.TrimRight(u.String(), "/")
		}
	}

	payload := map[string]interface{}{
		"name":       p.SkuName,
		"order_no":   p.OrderNo,
		"notify_url": fmt.Sprintf("%s/api/v4/payment/notify/custom/%s?ticket=%s&order_no=%s", siteURL, provider.ID, p.ResumeTicket, p.OrderNo),
		"amount":     p.Amount,
		"currency":   p.Currency,
	}
	body, _ := json.Marshal(payload)
	path := "/order"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	sign := crSign(string(body), path, timestamp, cfg.CommunicationKey)

	status, respBody, err := httpPostJSON(cfg.GatewayURL+path, body, 15*time.Second, map[string]string{
		"Content-Type":  "application/json",
		"Authorization": fmt.Sprintf("sign=%s t=%s", sign, timestamp),
		"X-Cr-Site-Url": siteURL,
	})
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("gateway HTTP %d: %s", status, truncate(string(respBody), 120))
	}
	var resp struct {
		Code int    `json:"code"`
		Data string `json:"data"`
		Err  string `json:"error"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("invalid gateway response: %w", err)
	}
	if resp.Code != 0 || resp.Data == "" {
		return "", fmt.Errorf("gateway error: %s", resp.Err)
	}
	return resp.Data, nil
}

// pollCustom queries the custom gateway for order status.
func pollCustom(c *gin.Context, db *ent.Client, provider Provider, p *ent.Payment) bool {
	cfg := parseCustomConfig(provider.Config)
	dep := dependencyFromGin(c)
	siteURL := ""
	if dep != nil {
		if u := dep.SettingProvider().SiteURL(c); u != nil {
			siteURL = strings.TrimRight(u.String(), "/")
		}
	}
	path := "/order"
	q := url.Values{}
	q.Set("order_no", p.OrderNo)
	full := path + "?" + q.Encode()
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	sign := crSign("", full, timestamp, cfg.CommunicationKey)

	status, body, err := httpGetJSON(cfg.GatewayURL+full, 15*time.Second, map[string]string{
		"Authorization": fmt.Sprintf("sign=%s t=%s", sign, timestamp),
		"X-Cr-Site-Url": siteURL,
	})
	if err != nil || status != http.StatusOK {
		return false
	}
	var resp struct {
		Code int    `json:"code"`
		Data string `json:"data"` // "paid" / "unpaid"
	}
	if json.Unmarshal(body, &resp) != nil || resp.Code != 0 {
		return false
	}
	if resp.Data == "paid" {
		_ = markPaid(c.Request.Context(), db, p, "")
		writePaymentEvent(c, dep.DBClient(), eventtype.PaymentPaid, p)
		return true
	}
	return false
}

// CustomNotify handles GET notify_url from the custom gateway.
// The ticket embedded in the URL authenticates the gateway.
func CustomNotify(c *gin.Context, providerID string) {
	dep := dependencyFromGin(c)
	db := dep.DBClient()
	provider, ok := GetProviderByID(c.Request.Context(), db, providerID)
	if !ok || provider.Type != ChannelCustom {
		c.JSON(404, map[string]string{"error": "provider not found"})
		return
	}
	orderNo := c.Query("order_no")
	ticket := c.Query("ticket")
	if orderNo == "" || ticket == "" {
		c.JSON(400, map[string]string{"error": "missing parameters"})
		return
	}
	p, err := db.Payment.Query().Where(payment.OrderNoEQ(orderNo)).First(c.Request.Context())
	if err != nil || p.ResumeTicket != ticket {
		c.JSON(404, map[string]string{"error": "order not found"})
		return
	}
	if p.Status != PaymentStatusUnpaid {
		c.JSON(200, map[string]interface{}{"code": 0}) // idempotent
		return
	}

	// Trust the gateway (communication key configured site-wide): fulfill.
	handleNotify(c, db, p, "custom:"+provider.Name)
	c.JSON(200, map[string]interface{}{"code": 0})
}

// ─── storage fulfillment wiring ───────────────────────────────

// The fs Capacity calculation must include purchased extra storage. This
// helper is referenced by dbfs.Capacity via the settings lookup.
func ExtraStorageFor(db *ent.Client, userID int) int64 {
	return loadExtraStorage(context.Background(), db, userID)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// httpGetJSON performs a GET request and returns status + body.
func httpGetJSON(rawURL string, timeout time.Duration, headers map[string]string) (int, []byte, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}

// httpPostJSON performs a POST request with a JSON body.
func httpPostJSON(rawURL string, body []byte, timeout time.Duration, headers map[string]string) (int, []byte, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("POST", rawURL, strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}
