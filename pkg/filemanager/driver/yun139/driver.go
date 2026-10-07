package yun139

// Cloudreve 存储策略适配器（Handler）——移动云盘
//
// 路径映射：Entity.Source()（SavePath）↔ 移动云盘根目录(RootFolderID) 下的同结构目录树。
// 上传后把 SavePath→fileId 缓存（进程内 5 分钟 TTL），Source/Delete 按需列目录解析。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/driver"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	"github.com/cloudreve/Cloudreve/v4/pkg/util"
)

var (
	capabilities = &driver.Capabilities{
		StaticFeatures: &boolset.BooleanSet{},
		MaxSourceExpire: time.Hour,
		MinSourceExpire: 0,
	}
)

func init() {
	boolset.Sets(map[driver.HandlerCapability]bool{
		driver.HandlerCapabilityProxyRequired: true,
	}, capabilities.StaticFeatures)
}

// ---------- SavePath → fileId 缓存（进程级） ----------

type cacheEntry struct {
	fileID  string
	folder  bool
	expires time.Time
}

var (
	pathCacheMu sync.RWMutex
	pathCache   = map[string]cacheEntry{}
)

func cacheKey(policyID int, p string) string {
	return fmt.Sprintf("%d:%s", policyID, p)
}

func cacheGet(policyID int, p string) (cacheEntry, bool) {
	pathCacheMu.RLock()
	defer pathCacheMu.RUnlock()
	e, ok := pathCache[cacheKey(policyID, p)]
	if !ok || time.Now().After(e.expires) {
		return cacheEntry{}, false
	}
	return e, true
}

func cacheSet(policyID int, p, fileID string, folder bool) {
	pathCacheMu.Lock()
	defer pathCacheMu.Unlock()
	pathCache[cacheKey(policyID, p)] = cacheEntry{fileID: fileID, folder: folder, expires: time.Now().Add(5 * time.Minute)}
}

func cacheDelete(policyID int, p string) {
	pathCacheMu.Lock()
	defer pathCacheMu.Unlock()
	delete(pathCache, cacheKey(policyID, p))
}

// ---------- Driver ----------

type Driver struct {
	Policy     *ent.StoragePolicy
	settings   *setting.Provider
	l          logging.Logger
	config     conf.ConfigProvider
	client     *Client
	policyInfo *PolicyInfo
}

// New constructs a new yun139 driver
func New(ctx context.Context, policy *ent.StoragePolicy, config conf.ConfigProvider, l logging.Logger) (*Driver, error) {
	info := policyInfoFrom(policy)
	if info.Authorization == "" && info.Username == "" {
		return nil, errors.New("移动云盘策略未配置 Authorization（或邮箱 Cookie + 用户名 + 密码 用于自动续期）")
	}
	// 无 Token 但有密码登录凭据 → 登录拿 Token
	if info.Authorization == "" {
		auth, _, err := RenewToken(ctx, info)
		if err != nil {
			return nil, fmt.Errorf("移动云盘登录失败: %w", err)
		}
		info.Authorization = auth
	}
	return &Driver{
		Policy:     policy,
		l:          l,
		config:     config,
		client:     NewClient(info, func(newAuth string) { persistToken(policy, newAuth) }),
		policyInfo: info,
	}, nil
}

func policyInfoFrom(policy *ent.StoragePolicy) *PolicyInfo {
	s := policy.Settings
	info := &PolicyInfo{
		Authorization: policy.AccessKey,
		RootFolderID:  "/",
	}
	if s != nil {
		info.Username = s.Yun139Username
		info.Password = s.Yun139Password
		info.MailCookies = s.Yun139MailCookies
		if s.Yun139RootFolderID != "" {
			info.RootFolderID = s.Yun139RootFolderID
		}
		if s.Yun139Token != "" {
			info.Authorization = s.Yun139Token
		}
	}
	info.Authorization = normalizeAuth(info.Authorization)
	return info
}

// persistToken 续期后回写策略 AccessKey（清除缓存）
func persistToken(policy *ent.StoragePolicy, newAuth string) {
	if newAuth == "" || policy == nil || policy.ID == 0 {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			// 上下文无依赖时忽略（如测试环境）
		}
	}()
	ctx := context.Background()
	dep := dependency.FromContext(ctx)
	if dep == nil {
		return
	}
	client := dep.StoragePolicyClient()
	if client == nil {
		return
	}
	updated := *policy
	updated.AccessKey = newAuth
	if err := client.UpdateAccessKey(ctx, &updated, newAuth); err != nil {
		dep.Logger().Warning("failed to persist renewed yun139 token: %s", err)
	}
}

// ---------- 路径映射 ----------

func (d *Driver) remoteRoot() string {
	if d.policyInfo.RootFolderID == "" {
		return "/"
	}
	return d.policyInfo.RootFolderID
}

// resolvePath 把 SavePath 解析成远端 fileId（含目录自动定位；上传目录自动创建）
func (d *Driver) resolvePath(ctx context.Context, savePath string, createDirs bool) (string, bool, error) {
	clean := path.Clean("/" + strings.ReplaceAll(savePath, "\\", "/"))
	if clean == "/" || clean == "." {
		return d.remoteRoot(), true, nil
	}
	if e, ok := cacheGet(d.Policy.ID, clean); ok {
		return e.fileID, e.folder, nil
	}
	cur := d.remoteRoot()
	parts := strings.Split(strings.Trim(clean, "/"), "/")
	for i, name := range parts {
		if name == "" {
			continue
		}
		sub := "/" + strings.Join(parts[:i+1], "/")
		if e, ok := cacheGet(d.Policy.ID, sub); ok {
			cur = e.fileID
			continue
		}
		items, err := d.client.List(ctx, cur)
		if err != nil {
			return "", false, err
		}
		found := ""
		for _, it := range items {
			if it.Name == name {
				found = it.FileID
				cacheSet(d.Policy.ID, sub, it.FileID, it.IsFolder())
				break
			}
		}
		if found == "" {
			if !createDirs {
				return "", false, fs.ErrPathNotExist
			}
			fid, err := d.client.CreateFolder(ctx, cur, name)
			if err != nil {
				return "", false, err
			}
			found = fid
			cacheSet(d.Policy.ID, sub, fid, true)
		}
		cur = found
	}
	isFolder := true
	if e, ok := cacheGet(d.Policy.ID, clean); ok {
		isFolder = e.folder
	} else {
		// 最后一段是文件时（上传完才有 fileId），缓存未命中则按目录处理
		cacheSet(d.Policy.ID, clean, cur, isFolder)
	}
	return cur, isFolder, nil
}

// ---------- Handler ----------

// Put 上传文件（服务端中转：SHA256 → 秒传/分片 → complete）
func (d *Driver) Put(ctx context.Context, file *fs.UploadRequest) error {
	if err := d.ensureToken(ctx); err != nil {
		return err
	}
	savePath := file.Props.SavePath
	parentPath := path.Dir(savePath)
	name := path.Base(savePath)

	parentID, _, err := d.resolvePath(ctx, parentPath, true)
	if err != nil {
		return fmt.Errorf("解析远端目录失败: %w", err)
	}

	// 需要 SHA256 + 分片读取：非 seek 流先落临时文件
	src := file.File
	seeker := file.Seeker
	var tmp *os.File
	if seeker == nil {
		tmp, err = os.CreateTemp(util.DataPath("temp"), "yun139-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		if _, err := io.Copy(tmp, file); err != nil {
			tmp.Close()
			return err
		}
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			tmp.Close()
			return err
		}
		src = tmp
		seeker = tmp
	}

	// SHA256（seek 到头部算完再回来）
	if _, err := seeker.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.LimitReader(src, file.Props.Size)); err != nil {
		return err
	}
	sha256Hex := hex.EncodeToString(hasher.Sum(nil))
	if _, err := seeker.Seek(0, io.SeekStart); err != nil {
		return err
	}

	task, err := d.client.CreateUpload(ctx, parentID, name, file.Props.Size, sha256Hex, file.Props.MimeType)
	if err != nil {
		return err
	}
	if task.Exist {
		// 秒传
		cacheSet(d.Policy.ID, savePath, task.FileID, false)
		return nil
	}
	// 逐片读取上传
	readAll := int64(0)
	for _, part := range task.Parts {
		if _, err := seeker.Seek(part.Offset, io.SeekStart); err != nil {
			return err
		}
		var reader io.Reader = io.LimitReader(src, part.PartSize)
		var hasher2 hash.Hash
		_ = hasher2
		if err := d.client.PutPart(ctx, part.UploadURL, reader, part.PartSize); err != nil {
			return err
		}
		readAll += part.PartSize
		_ = readAll
	}
	if err := d.client.Complete(ctx, task.FileID, task.UploadID, sha256Hex); err != nil {
		return err
	}
	cacheSet(d.Policy.ID, savePath, task.FileID, false)
	return nil
}

// Delete 删除文件/目录（回收站）
func (d *Driver) Delete(ctx context.Context, files ...string) ([]string, error) {
	var failed []string
	for _, p := range files {
		if err := d.ensureToken(ctx); err != nil {
			failed = append(failed, p)
			continue
		}
		fileID, _, err := d.resolvePath(ctx, p, false)
		if err != nil {
			// 远端不存在视为已删除
			continue
		}
		if err := d.client.Trash(ctx, []string{fileID}); err != nil {
			failed = append(failed, p)
		} else {
			cacheDelete(d.Policy.ID, p)
		}
	}
	return failed, nil
}

// Source 外链/下载直链
func (d *Driver) Source(ctx context.Context, e fs.Entity, args *driver.GetSourceArgs) (string, error) {
	if err := d.ensureToken(ctx); err != nil {
		return "", err
	}
	fileID, _, err := d.resolvePath(ctx, e.Source(), false)
	if err != nil {
		return "", err
	}
	u, err := d.client.GetDownloadURL(ctx, fileID)
	if err != nil {
		return "", err
	}
	if args.IsDownload && args.DisplayName != "" {
		// 移动云盘直链不支持 content-disposition 参数，改由响应头处理；此处原样返回
	}
	return u, nil
}

// Thumb 移动云盘缩略图（v1 不支持，走 Cloudreve 本地生成由前端开关控制）
func (d *Driver) Thumb(ctx context.Context, expire *time.Time, ext string, e fs.Entity) (string, error) {
	return "", errors.New("移动云盘暂不支持原生缩略图")
}

// Token 中转上传模式不使用客户端直传凭证
func (d *Driver) Token(ctx context.Context, uploadSession *fs.UploadSession, file *fs.UploadRequest) (*fs.UploadCredential, error) {
	return nil, errors.New("移动云盘策略仅支持服务端中转上传")
}

// CancelToken 无状态会话
func (d *Driver) CancelToken(ctx context.Context, uploadSession *fs.UploadSession) error {
	return nil
}

// CompleteUpload 中转上传完成时无需额外操作
func (d *Driver) CompleteUpload(ctx context.Context, session *fs.UploadSession) error {
	return nil
}

// List 递归列出远端目录
func (d *Driver) List(ctx context.Context, base string, onProgress driver.ListProgressFunc, recursive bool) ([]fs.PhysicalObject, error) {
	if err := d.ensureToken(ctx); err != nil {
		return nil, err
	}
	var res []fs.PhysicalObject
	root := path.Clean("/" + strings.ReplaceAll(base, "\\", "/"))
	var walk func(remoteParent string, relPrefix string) error
	walk = func(remoteParent string, relPrefix string) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		items, err := d.client.List(ctx, remoteParent)
		if err != nil {
			return err
		}
		for _, it := range items {
			rel := it.Name
			if relPrefix != "" {
				rel = relPrefix + "/" + it.Name
			}
			if it.IsFolder() {
				res = append(res, fs.PhysicalObject{
					Name:         it.Name,
					RelativePath: rel,
					Source:       path.Join(root, rel),
					Size:         0,
					IsDir:        true,
					LastModify:  parse139Time(it.UpdatedAt),
				})
				if recursive {
					if err := walk(it.FileID, rel); err != nil {
						return err
					}
				}
				continue
			}
			res = append(res, fs.PhysicalObject{
				Name:         it.Name,
				RelativePath: rel,
				Source:       path.Join(root, rel),
				Size:         it.Size,
				IsDir:        false,
				LastModify:  parse139Time(it.UpdatedAt),
			})
		}
		return nil
	}
	remoteParent, _, err := d.resolvePath(ctx, base, false)
	if err != nil {
		// 目录不存在 → 视为空
		return res, nil
	}
	if err := walk(remoteParent, ""); err != nil {
		return nil, err
	}
	return res, nil
}

// Capabilities 能力声明
func (d *Driver) Capabilities() *driver.Capabilities {
	return capabilities
}

// MediaMeta 不支持原生媒体元信息
func (d *Driver) MediaMeta(ctx context.Context, path, ext, language string) ([]driver.MediaMeta, error) {
	return nil, nil
}

// ensureToken 确保 Token 可用（无 Token 时尝试密码登录；快过期时自动续期）
func (d *Driver) ensureToken(ctx context.Context) error {
	if normalizeAuth(d.policyInfo.Authorization) == "" {
		auth, _, err := RenewToken(ctx, d.policyInfo)
		if err != nil {
			return err
		}
		d.policyInfo.Authorization = auth
		d.client.Policy.Authorization = auth
		persistToken(d.Policy, auth)
		return nil
	}
	// 剩余 < 15 天自动续期
	if rem := AuthRemainingMS(d.policyInfo.Authorization); rem >= 0 && rem < 1000*60*60*24*15 {
		if auth, source, err := RenewToken(ctx, d.policyInfo); err == nil && auth != "" {
			if source != "keep" {
				d.policyInfo.Authorization = auth
				d.client.Policy.Authorization = auth
				persistToken(d.Policy, auth)
				d.l.Info("移动云盘 Token 已自动续期 (%s)", source)
			}
		}
	}
	return nil
}

func parse139Time(s string) time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t
	}
	return time.Time{}
}

// Open 仅 InboundGet 能力驱动需要；移动云盘走外链，不实现
func (d *Driver) Open(ctx context.Context, path string) (*os.File, error) {
	return nil, errors.New("移动云盘策略不支持本地打开文件")
}

// LocalPath 同上
func (d *Driver) LocalPath(ctx context.Context, path string) string {
	return ""
}
