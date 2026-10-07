package yun139

// 移动云盘（中国移动云盘 / 和彩云，139）个人云 API 客户端。
// 实现依据：OpenList drivers/139 + 工作区 fts (file-transfer-system) 生产实现 + yun139-tool (MIT)。

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// PersonalAPIHost 个人云 API 主机
	PersonalAPIHost = "https://personal-kd-njs.yun.139.com"
	// PartSize 分片大小（与 OpenList 一致 100MB）
	PartSize = 100 * 1024 * 1024
	// maxPartsPerCall create/getUploadUrl 单次最多返回 100 片地址
	maxPartsPerCall = 100
)

// PolicyInfo 驱动所需的策略配置（来自 ent.StoragePolicy）
type PolicyInfo struct {
	Authorization string // Basic base64 部分里的 base64（不含 "Basic " 前缀）
	Account       string // 手机号（可从 token 解出，可选）
	Username      string // 邮箱账号（密码登录回退用，可空）
	Password      string // 邮箱密码（可空）
	MailCookies   string // mail.10086.cn Cookie（含 Os_SSo_Sid / RMKEY，可空）
	RootFolderID  string // 远端根目录 parentFileId（"/" = 个人云根目录）
}

// normalizeAuth 去掉可能误粘的 "Basic " 前缀
func normalizeAuth(auth string) string {
	t := strings.TrimSpace(auth)
	if strings.HasPrefix(strings.ToLower(t), "basic ") {
		t = strings.TrimSpace(t[6:])
	}
	return t
}

func randString16() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 16)
	rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

func md5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// calSign 计算 Mcloud-Sign 的第三段（OpenList 同款算法）
func calSign(body, ts, randStr string) string {
	// encodeURIComponent 全量转义（!'()* 也转义）
	var sb strings.Builder
	for _, r := range body {
		enc := percentEncodeRune(r)
		sb.WriteString(enc)
	}
	encoded := sb.String()
	chars := strings.Split(encoded, "")
	sort.Strings(chars)
	sorted := strings.Join(chars, "")
	b64 := base64.StdEncoding.EncodeToString([]byte(sorted))
	inner := md5Hex(b64)
	outer := md5Hex(inner + md5Hex(ts+":"+randStr))
	return strings.ToUpper(outer)
}

func percentEncodeRune(r rune) string {
	s := string(r)
	if s == "!" || s == "'" || s == "(" || s == ")" || s == "*" {
		return "%" + strings.ToUpper(fmt.Sprintf("%04x", int(r))[2:])
	}
	// 与 JS encodeURIComponent 一致：仅保留 unreserved
	if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
		r == '-' || r == '_' || r == '.' || r == '~' {
		return s
	}
	if r > 0x7FF {
		return "%" + strings.ToUpper(fmt.Sprintf("%06x", r)[2:])
	}
	return "%" + strings.ToUpper(fmt.Sprintf("%04x", r)[2:])
}

// callTime 139 要求的时间格式 "2006-01-02 15:04:05"
func callTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

// Client 单策略客户端（含自动续期状态）
type Client struct {
	Policy *PolicyInfo
	HTTP   *http.Client
	l      interface {
		Info(format string, v ...interface{})
		Warning(format string, v ...interface{})
	}
	// OnTokenRenewed 续期成功回调（用于持久化回策略 AccessKey）
	OnTokenRenewed func(newAuth string)
}

func NewClient(p *PolicyInfo, onRenewed func(string)) *Client {
	return &Client{Policy: p, HTTP: &http.Client{Timeout: 120 * time.Second}, OnTokenRenewed: onRenewed}
}

// AccountFromAuth 从 base64 token 解出手机号
func AccountFromAuth(auth string) string {
	raw, err := base64.StdEncoding.DecodeString(normalizeAuth(auth))
	if err != nil {
		return ""
	}
	parts := strings.SplitN(string(raw), ":", 3)
	if len(parts) < 2 {
		return ""
	}
	acc := parts[1]
	if idx := strings.Index(acc, "|"); idx >= 0 {
		acc = acc[:idx]
	}
	if len(acc) < 5 || !isDigits(acc) {
		return ""
	}
	return acc
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func (c *Client) buildHeaders(body string) http.Header {
	ts := callTime(time.Now())
	randStr := randString16()
	sign := calSign(body, ts, randStr)
	h := http.Header{}
	h.Set("Accept", "application/json, text/plain, */*")
	h.Set("Authorization", "Basic "+normalizeAuth(c.Policy.Authorization))
	h.Set("Content-Type", "application/json;charset=UTF-8")
	h.Set("Caller", "web")
	h.Set("Cms-Device", "default")
	h.Set("Mcloud-Channel", "1000101")
	h.Set("Mcloud-Client", "10701")
	h.Set("Mcloud-Route", "001")
	h.Set("Mcloud-Sign", ts+","+randStr+","+sign)
	h.Set("Mcloud-Version", "7.14.0")
	h.Set("x-DeviceInfo", "||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||")
	h.Set("x-huawei-channelSrc", "10000034")
	h.Set("x-inner-ntwk", "2")
	h.Set("x-m4c-caller", "PC")
	h.Set("x-m4c-src", "10002")
	h.Set("x-SvcType", "1")
	h.Set("X-Yun-Api-Version", "v1")
	h.Set("X-Yun-App-Channel", "10000034")
	h.Set("X-Yun-Channel-Source", "10000034")
	h.Set("X-Yun-Client-Info", "||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||dW5kZWZpbmVk||")
	h.Set("X-Yun-Module-Type", "100")
	h.Set("X-Yun-Svc-Type", "1")
	h.Set("Origin", "https://yun.139.com")
	h.Set("Referer", "https://yun.139.com/w/")
	h.Set("User-Agent", "Mozilla/5.0 ZXFile/1.0")
	return h
}

// APIError 业务错误
type APIError struct {
	Code    string
	Message string
	AuthFail bool
}

func (e *APIError) Error() string {
	if e.AuthFail {
		return "云盘鉴权失败 (" + e.Code + " " + e.Message + ")"
	}
	return "移动云盘接口错误 (" + e.Code + " " + e.Message + ")"
}

// Post 调用个人云 API；鉴权失败时自动尝试续期一次
func (c *Client) Post(ctx context.Context, pathname string, data interface{}) (map[string]interface{}, error) {
	for attempt := 0; attempt < 2; attempt++ {
		body, _ := json.Marshal(data)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, PersonalAPIHost+pathname, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header = c.buildHeaders(string(body))
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, err
		}
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, io.LimitReader(resp.Body, 1<<20)); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()
		text := buf.String()
		var j map[string]interface{}
		if err := json.Unmarshal([]byte(text), &j); err != nil {
			return nil, fmt.Errorf("云盘响应无效 HTTP %d: %s", resp.StatusCode, truncate(text, 160))
		}
		msg, _ := j["message"].(string)
		code, _ := j["code"].(string)
		success := true
		if v, ok := j["success"].(bool); ok {
			success = v
		}
		authFail := strings.Contains(msg, "认证失败") || strings.Contains(msg, "05050006") ||
			code == "05050006" || code == "401" || code == "403"
		if authFail && attempt == 0 {
			// 自动续期后重试一次
			if newAuth, _, rerr := RenewToken(ctx, c.Policy); rerr == nil && newAuth != "" {
				c.Policy.Authorization = newAuth
				continue
			}
		}
		if resp.StatusCode >= 400 {
			return nil, &APIError{Code: code, Message: truncate(msg, 120), AuthFail: authFail}
		}
		if !success {
			return nil, &APIError{Code: code, Message: truncate(msg, 160), AuthFail: authFail}
		}
		if code != "" && code != "0000" && code != "0" && code != "success" && !success {
			return nil, &APIError{Code: code, Message: truncate(msg, 160), AuthFail: authFail}
		}
		return j, nil
	}
	return nil, errors.New("云盘请求失败（重试后仍鉴权失败）")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---------- 数据结构 ----------

type FileItem struct {
	FileID       string `json:"fileId"`
	ParentFileID string `json:"parentFileId"`
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	Type         string `json:"type"` // folder | file
	UpdatedAt    string `json:"updatedAt"`
	CreatedAt    string `json:"createdAt"`
	ContentHash  string `json:"contentHash"`
}

func (f FileItem) IsFolder() bool { return f.Type == "folder" }

// List 列出目录（分页聚合）
func (c *Client) List(ctx context.Context, parentFileID string) ([]FileItem, error) {
	var out []FileItem
	cursor := ""
	for {
		body := map[string]interface{}{
			"imageThumbnailStyleList": []string{"Small", "Large"},
			"orderBy":                 "updated_at",
			"orderDirection":          "DESC",
			"pageInfo":                map[string]interface{}{"pageCursor": cursor, "pageSize": 100},
			"parentFileId":            parentFileID,
		}
		j, err := c.Post(ctx, "/file/list", body)
		if err != nil {
			return nil, err
		}
		data, _ := j["data"].(map[string]interface{})
		items, _ := data["items"].([]interface{})
		for _, it := range items {
			m, ok := it.(map[string]interface{})
			if !ok {
				continue
			}
			out = append(out, FileItem{
				FileID:    str(m["fileId"]),
				Name:      str(m["name"]),
				Size:      int64(num(m["size"])),
				Type:      str(m["type"]),
				UpdatedAt: str(m["updatedAt"]),
			})
		}
		cursor = str(data["nextPageCursor"])
		if cursor == "" || len(items) == 0 {
			break
		}
	}
	return out, nil
}

// CreateFolder 创建目录，返回 fileId
func (c *Client) CreateFolder(ctx context.Context, parentFileID, name string) (string, error) {
	j, err := c.Post(ctx, "/file/create", map[string]interface{}{
		"parentFileId":    parentFileID,
		"name":            name,
		"description":     "",
		"type":            "folder",
		"fileRenameMode":  "force_rename",
	})
	if err != nil {
		return "", err
	}
	if id := pickFileID(j); id != "" {
		return id, nil
	}
	// create 有时只返回成功，不回 fileId → 列目录补查
	items, err := c.List(ctx, parentFileID)
	if err != nil {
		return "", err
	}
	for _, it := range items {
		if it.IsFolder() && it.Name == name {
			return it.FileID, nil
		}
	}
	return "", errors.New("创建目录失败：未返回 fileId")
}

// Rename 重命名
func (c *Client) Rename(ctx context.Context, fileID, newName string) error {
	_, err := c.Post(ctx, "/file/update", map[string]interface{}{"fileId": fileID, "name": newName})
	return err
}

// Move 批量移动
func (c *Client) Move(ctx context.Context, fileIDs []string, toParentFileID string) error {
	_, err := c.Post(ctx, "/file/batchMove", map[string]interface{}{"fileIds": fileIDs, "toParentFileId": toParentFileID})
	return err
}

// Trash 批量放入回收站（删除）
func (c *Client) Trash(ctx context.Context, fileIDs []string) error {
	_, err := c.Post(ctx, "/recyclebin/batchTrash", map[string]interface{}{"fileIds": fileIDs})
	return err
}

// GetDownloadURL 取直链
func (c *Client) GetDownloadURL(ctx context.Context, fileID string) (string, error) {
	j, err := c.Post(ctx, "/file/getDownloadUrl", map[string]interface{}{"fileId": fileID})
	if err != nil {
		return "", err
	}
	data, _ := j["data"].(map[string]interface{})
	if data == nil {
		return "", errors.New("无法获取云盘下载链接")
	}
	if cdn, _ := data["cdnUrl"].(string); cdn != "" {
		return cdn, nil
	}
	if u, _ := data["url"].(string); u != "" {
		return u, nil
	}
	return "", errors.New("无法获取云盘下载链接")
}

// UploadTask 上传任务
type UploadTask struct {
	FileID   string
	UploadID string
	Exist    bool // 秒传
	Rapid    bool
	Parts    []UploadPart
}

type UploadPart struct {
	PartNumber int64
	PartSize   int64
	Offset     int64
	UploadURL  string
}

// CreateUpload 创建上传任务（contentHash 为 SHA256 hex 小写）
func (c *Client) CreateUpload(ctx context.Context, parentFileID, name string, size int64, sha256Hex, contentType string) (*UploadTask, error) {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	nParts := int((size + PartSize - 1) / PartSize)
	if nParts < 1 {
		nParts = 1
	}
	partInfos := make([][]interface{}, 0, nParts)
	for i := 0; i < nParts; i++ {
		start := int64(i) * PartSize
		ps := size - start
		if ps > PartSize {
			ps = PartSize
		}
		partInfos = append(partInfos, []interface{}{
			map[string]interface{}{"partNumber": i + 1, "partSize": ps, "parallelHashCtx": map[string]interface{}{"partOffset": start}},
		})
	}
	// create 只接受扁平 partInfos 数组
	flat := make([]map[string]interface{}, 0, nParts)
	for _, p := range partInfos {
		flat = append(flat, p[0].(map[string]interface{}))
	}
	if len(flat) > maxPartsPerCall {
		flat = flat[:maxPartsPerCall]
	}
	body := map[string]interface{}{
		"contentHash":           strings.ToLower(sha256Hex),
		"contentHashAlgorithm":  "SHA256",
		"contentType":           contentType,
		"parallelUpload":        false,
		"partInfos":             flat,
		"size":                  size,
		"parentFileId":          parentFileID,
		"name":                  name,
		"type":                  "file",
		"fileRenameMode":        "auto_rename",
		"userRegion":            map[string]interface{}{"cityCode": "854", "provinceCode": "851"},
	}
	j, err := c.Post(ctx, "/file/create", body)
	if err != nil {
		return nil, err
	}
	data, _ := j["data"].(map[string]interface{})
	task := &UploadTask{
		FileID:   str(data["fileId"]),
		UploadID: str(data["uploadId"]),
		Exist:    truthy(data["exist"]),
		Rapid:    truthy(data["rapidUpload"]),
	}
	if task.FileID == "" {
		return nil, errors.New("云盘创建上传任务失败：未返回 fileId")
	}
	if task.Exist {
		return task, nil // 秒传
	}
	urlMap := map[int64]UploadPart{}
	for _, up := range toSlice(data["partInfos"]) {
		pn := int64(num(up["partNumber"]))
		if pn == 0 {
			pn = int64(len(urlMap) + 1)
		}
		u := str(up["uploadUrl"])
		if u == "" {
			u = str(up["cdnUploadUrl"])
		}
		ps := int64(num(up["partSize"]))
		if ps == 0 {
			ps = partSizeOf(size, PartSize, pn)
		}
		if u != "" {
			urlMap[pn] = UploadPart{PartNumber: pn, PartSize: ps, Offset: (pn - 1) * PartSize, UploadURL: u}
		}
	}
	// 100 片一批续取
	for got := len(urlMap); got < nParts; got = len(urlMap) {
		start := got
		end := start + maxPartsPerCall
		if end > nParts {
			end = nParts
		}
		if end <= start {
			break
		}
		batch := make([]map[string]interface{}, 0, end-start)
		for i := start; i < end; i++ {
			batch = append(batch, map[string]interface{}{
				"partNumber": i + 1, "partSize": partSizeOf(size, PartSize, int64(i+1)),
				"parallelHashCtx": map[string]interface{}{"partOffset": int64(i) * PartSize},
			})
		}
		body := map[string]interface{}{"fileId": task.FileID, "uploadId": task.UploadID, "partInfos": batch}
		if acc := AccountFromAuth(c.Policy.Authorization); acc != "" {
			body["commonAccountInfo"] = map[string]interface{}{"account": acc, "accountType": 1}
		}
		more, err := c.Post(ctx, "/file/getUploadUrl", body)
		if err != nil {
			return nil, err
		}
		md, _ := more["data"].(map[string]interface{})
		gotAny := false
		for _, up := range toSlice(md["partInfos"]) {
			pn := int64(num(up["partNumber"]))
			u := str(up["uploadUrl"])
			if u == "" {
				u = str(up["cdnUploadUrl"])
			}
			if u != "" {
				urlMap[pn] = UploadPart{PartNumber: pn, PartSize: partSizeOf(size, PartSize, pn), Offset: (pn - 1) * PartSize, UploadURL: u}
				gotAny = true
			}
		}
		if !gotAny {
			break
		}
	}
	for pn, part := range urlMap {
		_ = pn
		task.Parts = append(task.Parts, part)
	}
	sortParts(task.Parts)
	return task, nil
}

func sortParts(parts []UploadPart) {
	for i := 1; i < len(parts); i++ {
		for j := i; j > 0 && parts[j].PartNumber < parts[j-1].PartNumber; j-- {
			parts[j], parts[j-1] = parts[j-1], parts[j]
		}
	}
}

func partSizeOf(size, partSize int64, partNumber int64) int64 {
	start := (partNumber - 1) * partSize
	ps := size - start
	if ps > partSize {
		ps = partSize
	}
	if ps < 0 {
		ps = 0
	}
	return ps
}

// PutPart PUT 单个分片（ctx 取消可中断）
func (c *Client) PutPart(ctx context.Context, uploadURL string, reader io.Reader, length int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, reader)
	if err != nil {
		return err
	}
	req.ContentLength = length
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Origin", "https://yun.139.com")
	req.Header.Set("Referer", "https://yun.139.com/")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		buf := new(bytes.Buffer)
		_, _ = io.Copy(buf, io.LimitReader(resp.Body, 1<<18))
		return fmt.Errorf("分片上传失败 HTTP %d: %s", resp.StatusCode, truncate(buf.String(), 160))
	}
	return nil
}

// Complete 完成上传
func (c *Client) Complete(ctx context.Context, fileID, uploadID, sha256Hex string) error {
	_, err := c.Post(ctx, "/file/complete", map[string]interface{}{
		"contentHash": strings.ToLower(sha256Hex), "contentHashAlgorithm": "SHA256",
		"fileId": fileID, "uploadId": uploadID,
	})
	return err
}

// Sha256Reader 边读边算（用于非 seek 流的暂存场景）
func Sha256Hex(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ---------- helpers ----------

func str(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func num(v interface{}) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int64:
		return float64(n)
	case int:
		return float64(n)
	case json.Number:
		f, _ := strconv.ParseFloat(string(n), 64)
		return f
	}
	return 0
}

func truthy(v interface{}) bool {
	b, ok := v.(bool)
	return ok && b
}

func toSlice(v interface{}) []map[string]interface{} {
	arr, _ := v.([]interface{})
	out := make([]map[string]interface{}, 0, len(arr))
	for _, it := range arr {
		if m, ok := it.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out
}

func pickFileID(j map[string]interface{}) string {
	data, _ := j["data"].(map[string]interface{})
	if data != nil {
		if id := str(data["fileId"]); id != "" {
			return id
		}
		if id := str(data["id"]); id != "" {
			return id
		}
	}
	if id := str(j["fileId"]); id != "" {
		return id
	}
	return ""
}
