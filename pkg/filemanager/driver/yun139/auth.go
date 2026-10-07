package yun139

// Authorization 自动续期（移植自工作区 fts app/core/yun139_auth.py，与 OpenList drivers/139/util.go 对齐）：
//  1. authTokenRefresh.do —— 剩余有效期 > 15 天则跳过；成功返回新 token
//  2. 密码登录回退（需要 邮箱 Cookie + 用户名 + 密码）：
//     mail.10086.cn 密码登录 → getArtifact → thirdlogin（AES 加密请求）→ 新 Authorization

import (
	"bytes"
	"context"
	cryptRand "crypto/rand"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	refreshURL     = "https://aas.caiyun.feixin.10086.cn:443/tellin/authTokenRefresh.do"
	mailLoginURL   = "https://mail.10086.cn/Login/Login.ashx"
	getArtifactURL = "https://smsrebuild1.mail.10086.cn/setting/s"
	thirdLoginURL  = "https://user-njs.yun.139.com/user/thirdlogin"

	keyHex1        = "73634235495062495331515373756c734e7253306c673d3d"
	keyHex2        = "7150714477323633586746674c337538"
	clientKeyDecrypt = "l3TryM&Q+X7@dzwk)qP"
)

// AuthRemainingMS 从 token 第 4 段解出过期时间（unix ms），解析失败返回 -1
func AuthRemainingMS(auth string) int64 {
	_, _, token, ok := parseAuthParts(auth)
	if !ok {
		return -1
	}
	strs := strings.Split(token, "|")
	if len(strs) < 4 {
		return -1
	}
	exp, err := strconv.ParseInt(strs[3], 10, 64)
	if err != nil {
		return -1
	}
	return exp - time.Now().UnixMilli()
}

// parseAuthParts 解 base64 Authorization → (prefix, account, tokenPart)
func parseAuthParts(auth string) (string, string, string, bool) {
	auth = strings.TrimSpace(auth)
	if strings.HasPrefix(strings.ToLower(auth), "basic ") {
		auth = strings.TrimSpace(auth[6:])
	}
	if auth == "" {
		return "", "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return "", "", "", false
	}
	parts := strings.SplitN(string(raw), ":", 3)
	if len(parts) < 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// RenewToken 续期 Authorization：
//   - 剩余 > 15 天 → 原样返回（keep）
//   - authTokenRefresh.do 成功 → 新 token
//   - 失败且有密码登录凭据 → 密码登录
//   - 都不行 → 错误
func RenewToken(ctx context.Context, p *PolicyInfo) (string, string, error) {
	auth := normalizeAuth(p.Authorization)
	source := "keep"
	if auth == "" {
		na, err := loginWithPassword(ctx, p)
		if err != nil {
			return "", "", fmt.Errorf("未配置 Authorization，且密码登录失败: %w", err)
		}
		return na, "password_login", nil
	}

	if rem := AuthRemainingMS(auth); rem > 1000*60*60*24*15 {
		return auth, "keep", nil
	}

	newAuth, err := doRefreshToken(ctx, auth)
	if err == nil && newAuth != "" {
		return newAuth, "refresh", nil
	}
	if err != nil {
		source = "refresh_fail: " + err.Error()
	}
	if p.Username != "" && p.Password != "" && p.MailCookies != "" {
		na, lerr := loginWithPassword(ctx, p)
		if lerr != nil {
			return "", "", fmt.Errorf("refresh 失败(%s)且密码登录失败(%v)", err, lerr)
		}
		return na, "password_login", nil
	}
	if rem := AuthRemainingMS(auth); rem >= 0 && rem < 0 {
		return "", "", errors.New("authorization 已过期且无密码登录回退")
	}
	return "", "", fmt.Errorf("token 续期失败(%s)，且未配置密码登录回退（邮箱 Cookie + 用户名 + 密码）", source)
}

// doRefreshToken authTokenRefresh.do（XML）
func doRefreshToken(ctx context.Context, auth string) (string, error) {
	_, account, token, ok := parseAuthParts(auth)
	if !ok {
		return "", errors.New("authorization decode failed")
	}
	body := fmt.Sprintf("<root><token>%s</token><account>%s</account><clienttype>656</clienttype></root>", token, account)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, refreshURL, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept", "application/xml, text/xml, */*")
	client := &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	text, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	s := string(text)
	ret := xmlTag(s, "return")
	newTok := xmlTag(s, "token")
	desc := xmlTag(s, "desc")
	if ret != "0" || newTok == "" {
		return "", fmt.Errorf("return=%s desc=%s", ret, desc)
	}
	newAuth := base64.StdEncoding.EncodeToString([]byte("pc:" + account + ":" + newTok))
	return newAuth, nil
}

func xmlTag(s, tag string) string {
	re := regexp.MustCompile(`(?i)<` + tag + `>([^<]*)</` + tag + `>`)
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// ---------- 密码登录（三步） ----------

func sha1Hex(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func pkcs7Pad(data []byte) []byte {
	n := 16 - len(data)%16
	return append(data, bytes.Repeat([]byte{byte(n)}, n)...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%16 != 0 {
		return nil, errors.New("bad padded data")
	}
	n := int(data[len(data)-1])
	if n < 1 || n > 16 || n > len(data) {
		return nil, errors.New("bad padding")
	}
	return data[:len(data)-n], nil
}

func aesCBCEncrypt(plain, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain = pkcs7Pad(plain)
	iv := make([]byte, 16)
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return append(iv, out...), nil
}

func aesCBCDecrypt(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(cipherText) < 16 || len(cipherText)%16 != 0 {
		return nil, errors.New("bad cbc data")
	}
	iv := cipherText[:16]
	out := make([]byte, len(cipherText)-16)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, cipherText[16:])
	return pkcs7Unpad(out)
}

func aesECBDecrypt(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(cipherText) == 0 || len(cipherText)%16 != 0 {
		return nil, errors.New("bad ecb data")
	}
	out := make([]byte, len(cipherText))
	for i := 0; i < len(cipherText); i += 16 {
		block.Decrypt(out[i:i+16], cipherText[i:i+16])
	}
	return pkcs7Unpad(out)
}

// sortedJSONStringify 与 OpenList 一致的排序 JSON 序列化（加密请求体用）
func sortedJSONStringify(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		b, _ := json.Marshal(t)
		return string(b)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		b, _ := json.Marshal(t)
		return string(b)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case []interface{}:
		parts := make([]string, 0, len(t))
		for _, it := range t {
			parts = append(parts, sortedJSONStringify(it))
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			kb, _ := json.Marshal(k)
			parts = append(parts, string(kb)+":"+sortedJSONStringify(t[k]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

// loginWithPassword 三步密码登录，返回新 Authorization（base64，无 Basic 前缀）
func loginWithPassword(ctx context.Context, p *PolicyInfo) (string, error) {
	if p.Username == "" || p.Password == "" || p.MailCookies == "" {
		return "", errors.New("密码登录需要 邮箱Cookie + 用户名 + 密码")
	}
	sid, cookies, err := step1MailLogin(ctx, p.Username, p.Password, p.MailCookies)
	if err != nil {
		return "", fmt.Errorf("邮箱登录失败: %w", err)
	}
	artifact, err := step2Artifact(ctx, sid, cookies)
	if err != nil {
		return "", fmt.Errorf("getArtifact 失败: %w", err)
	}
	auth, _, _, err := step3ThirdLogin(ctx, p.Username, artifact)
	if err != nil {
		return "", fmt.Errorf("thirdlogin 失败: %w", err)
	}
	return auth, nil
}

func step1MailLogin(ctx context.Context, username, password, mailCookies string) (string, string, error) {
	cguid := fmt.Sprintf("%d", time.Now().UnixMilli())
	uB64 := base64.StdEncoding.EncodeToString([]byte(username))
	form := url.Values{}
	form.Set("UserName", username)
	form.Set("passOld", "")
	form.Set("auto", "on")
	form.Set("Password", sha1Hex("fetion.com.cn:"+password))
	form.Set("webIndexPagePwdLogin", "1")
	form.Set("pwdType", "1")
	form.Set("clientId", "1003")
	form.Set("authType", "2")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mailLoginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://mail.10086.cn")
	req.Header.Set("Referer", "https://mail.10086.cn/default.html?&s=1&v=0&u="+uB64+"&m=1&ec=S001&resource=indexLogin&clientid=1003&auto=on&cguid="+cguid+"&mtime=45")
	req.Header.Set("Cookie", mailCookies)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0")
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	location := resp.Header.Get("Location")
	sid, cguid2 := extractParam(location, "sid"), extractParam(location, "cguid")
	merged := mailCookies
	for _, sc := range resp.Header.Values("Set-Cookie") {
		first := strings.SplitN(sc, ";", 2)[0]
		if eq := strings.Index(first, "="); eq > 0 {
			k, v := strings.TrimSpace(first[:eq]), strings.TrimSpace(first[eq+1:])
			merged = setCookieKV(merged, k, v)
		}
		if m := regexp.MustCompile(`Os_SSo_Sid=([^;]+)`).FindStringSubmatch(sc); m != nil && sid == "" {
			sid = m[1]
		}
		if m := regexp.MustCompile(`cguid=([^;]+)`).FindStringSubmatch(sc); m != nil && cguid2 == "" {
			cguid2 = m[1]
		}
	}
	if sid == "" {
		return "", "", errors.New("未拿到 sid（请检查账号密码与邮箱 Cookie，尤其 Os_SSo_Sid/RMKEY）")
	}
	if cguid2 != "" {
		merged = setCookieKV(merged, "cguid", cguid2)
	}
	return sid, merged, nil
}

func extractParam(raw, key string) string {
	m := regexp.MustCompile(key + `=([^&]+)`).FindStringSubmatch(raw)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func setCookieKV(cookieHeader, key, value string) string {
	parts := strings.Split(cookieHeader, ";")
	out := make([]string, 0, len(parts)+1)
	found := false
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(p), strings.ToLower(key)+"=") {
			out = append(out, key+"="+value)
			found = true
			continue
		}
		out = append(out, p)
	}
	if !found {
		out = append(out, key+"="+value)
	}
	return strings.Join(out, "; ")
}

func extractRMKey(mailCookies string) string {
	for _, part := range strings.Split(mailCookies, ";") {
		if strings.HasPrefix(strings.TrimSpace(part), "RMKEY=") {
			return strings.TrimSpace(part)
		}
	}
	return ""
}

func step2Artifact(ctx context.Context, sid, mailCookies string) (string, error) {
	cguid := fmt.Sprintf("%d", time.Now().UnixMilli())
	rmKey := extractRMKey(mailCookies)
	if rmKey == "" {
		return "", errors.New("MailCookies 中缺少 RMKEY（请从 mail.10086.cn 重新复制 Cookie）")
	}
	u := getArtifactURL + "?func=" + url.PathEscape("umc:getArtifact") + "&sid=" + url.QueryEscape(sid) + "&cguid=" + url.QueryEscape(cguid)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(""))
	if err != nil {
		return "", err
	}
	req.Header.Set("Cookie", rmKey)
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("User-Agent", "okhttp/4.12.0")
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	text, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var j map[string]interface{}
	if err := json.Unmarshal(text, &j); err != nil {
		m := regexp.MustCompile(`"artifact"\s*:\s*"([^"]+)"`).FindStringSubmatch(string(text))
		if m != nil {
			return m[1], nil
		}
		return "", fmt.Errorf("响应无效: %s", truncate(string(text), 160))
	}
	if varMap, ok := j["var"].(map[string]interface{}); ok {
		if a, _ := varMap["artifact"].(string); a != "" {
			return a, nil
		}
	}
	if a, _ := j["artifact"].(string); a != "" {
		return a, nil
	}
	return "", errors.New("getArtifact 未返回 artifact")
}

func step3ThirdLogin(ctx context.Context, username, dycpwd string) (string, string, string, error) {
	body := map[string]interface{}{
		"clientkey_decrypt": clientKeyDecrypt,
		"clienttype":        "886",
		"cpid":              "507",
		"dycpwd":            dycpwd,
		"extInfo":           map[string]interface{}{"ifOpenAccount": "0"},
		"loginMode":         "0",
		"msisdn":            username,
		"pintype":           "13",
		"secinfo":           strings.ToUpper(sha1Hex("fetion.com.cn:" + dycpwd)),
		"version":           "20250901",
	}
	headers := map[string]string{
		"hcy-cool-flag":        "1",
		"x-huawei-channelSrc":  "10246600",
		"x-sdk-channelSrc":     "",
		"x-MM-Source":          "0",
		"x-UserAgent":          "android|23116PN5BC|android15|1.2.6|||1440x3200|10246600",
		"x-DeviceInfo":         "4|127.0.0.1|5|1.2.6|Xiaomi|23116PN5BC||02-00-00-00-00-00|android 15|1440x3200|android|||",
		"Content-Type":         "text/plain;charset=UTF-8",
		"User-Agent":           "okhttp/3.12.2",
	}
	layer1, err := encryptedRequest(ctx, thirdLoginURL, body, headers, keyHex1)
	if err != nil {
		return "", "", "", err
	}
	var j1 map[string]interface{}
	if err := json.Unmarshal(layer1, &j1); err != nil {
		return "", "", "", fmt.Errorf("thirdlogin 响应解析失败: %w", err)
	}
	hexInner, _ := j1["data"].(string)
	if hexInner == "" {
		return "", "", "", errors.New("thirdlogin 缺少 data 字段")
	}
	inner, err := hex.DecodeString(hexInner)
	if err != nil {
		return "", "", "", fmt.Errorf("thirdlogin data 非 hex: %w", err)
	}
	key2, _ := hex.DecodeString(keyHex2)
	finalBytes, err := aesECBDecrypt(inner, key2)
	if err != nil {
		return "", "", "", fmt.Errorf("thirdlogin 解密失败: %w", err)
	}
	var final map[string]interface{}
	if err := json.Unmarshal(finalBytes, &final); err != nil {
		return "", "", "", fmt.Errorf("thirdlogin final 解析失败: %w", err)
	}
	authToken, _ := final["authToken"].(string)
	account, _ := final["account"].(string)
	udid, _ := final["userDomainId"].(string)
	if authToken == "" || account == "" {
		return "", "", "", errors.New("thirdlogin 未返回 authToken/account")
	}
	newAuth := base64.StdEncoding.EncodeToString([]byte("pc:" + account + ":" + authToken))
	return newAuth, account, udid, nil
}

// encryptedRequest OpenList 同款：排序 JSON → AES-CBC(key, iv 前置) → base64 POST；响应 base64 → 去掉 16 字节 iv → AES-CBC 解密
func encryptedRequest(ctx context.Context, rawURL string, body map[string]interface{}, headers map[string]string, aesKeyHex string) ([]byte, error) {
	aesKey, err := hex.DecodeString(aesKeyHex)
	if err != nil {
		return nil, err
	}
	sorted := sortedJSONStringify(body)
	iv := make([]byte, 16)
	if _, err := cryptRand.Read(iv); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	plain := pkcs7Pad([]byte(sorted))
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, plain)
	payload := base64.StdEncoding.EncodeToString(append(iv, ct...))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(buf), 160))
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
	if len(raw) > 0 && raw[0] == '{' {
		return raw, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil || len(decoded) < 16 {
		return nil, errors.New("加密响应过短")
	}
	return aesCBCDecrypt(decoded[16:], aesKey)
}

