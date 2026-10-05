package share

import (
	"context"
	"fmt"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	entfile "github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/eventtype"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/gin-gonic/gin"
)

type (
	// ShareCreateService 创建新分享服务
	ShareCreateService struct {
		Uri             string             `json:"uri" binding:"required"`
		IsPrivate       bool               `json:"is_private"`
		Password        string             `json:"password" binding:"omitempty,max=32,alphanum"`
		RemainDownloads int                `json:"downloads"`
		Expire          int                `json:"expire"`
		ShareView       bool               `json:"share_view"`
		ShowReadMe      bool               `json:"show_readme"`
		Permission      string             `json:"permission" binding:"omitempty,eq=read|eq=upload|eq=edit"`
		Grants          []types.ShareGrant `json:"grants"`
	}
	ShareCreateParamCtx struct{}

	BatchDeleteShareService struct {
		ShareIDs []string `json:"ids" binding:"required"`
	}
	BatchDeleteParamCtx struct{}
)

func (service *BatchDeleteShareService) Delete(c *gin.Context) error {
	dep := dependency.FromContext(c)
	uid := inventory.UserIDFromContext(c)
	shareClient := dep.ShareClient()

	var ids []int

	for _, v := range service.ShareIDs {
		id, err := dep.HashIDEncoder().Decode(v, hashid.ShareID)
		if err != nil {
			return fmt.Errorf("failed to decode hash id %q: %w", v, err)
		}

		ids = append(ids, id)
	}

	if err := shareClient.DeleteBatchByUserID(c, uid, ids); err != nil {
		return serializer.NewError(serializer.CodeDBError, "Failed to delete shares", err)
	}

	return nil
}

// Upsert 创建或更新分享
func (service *ShareCreateService) Upsert(c *gin.Context, existed int) (string, error) {
	dep := dependency.FromContext(c)
	user := inventory.UserFromContext(c)
	m := manager.NewFileManager(dep, user)
	defer m.Recycle()

	// Check group permission for creating share link
	if !user.Edges.Group.Permissions.Enabled(int(types.GroupPermissionShare)) {
		return "", serializer.NewError(serializer.CodeGroupNotAllowed, "Group permission denied", nil)
	}

	uri, err := fs.NewUriFromString(service.Uri)
	if err != nil {
		return "", serializer.NewError(serializer.CodeParamErr, "unknown uri", err)
	}

	var expires *time.Time
	if service.Expire > 0 {
		expires = new(time.Time)
		*expires = time.Now().Add(time.Duration(service.Expire) * time.Second)
	}

	share, err := m.CreateOrUpdateShare(c, uri, &manager.CreateShareArgs{
		IsPrivate:       service.IsPrivate,
		Password:        service.Password,
		RemainDownloads: service.RemainDownloads,
		Expire:          expires,
		ExistedShareID:  existed,
		ShareView:       service.ShareView,
		ShowReadMe:      service.ShowReadMe,
		Permission:      types.SharePermission(service.Permission),
		Grants:          service.Grants,
	})
	if err != nil {
		return "", err
	}

	base := dep.SettingProvider().SiteURL(c)
	shareName := ""
	if share.Edges.File != nil {
		shareName = share.Edges.File.Name
	}
	explorer.WriteAudit(c, eventtype.Share, "share", shareName, nil)
	return explorer.BuildShareLink(share, dep.HashIDEncoder(), base, true), nil
}

type (
	// RedeemService saves a share (by ID + password) as a shortcut in the
	// current user's "Shared with me" list.
	RedeemService struct {
		ID       string `json:"id" binding:"required"`
		Password string `json:"password"`
	}
	RedeemParamCtx struct{}
)

// Redeem creates a symbolic file pointing to the shared file, so that it
// shows up in the user's "Shared with me" navigator.
func (service *RedeemService) Redeem(c *gin.Context) error {
	dep := dependency.FromContext(c)
	user := inventory.UserFromContext(c)

	if inventory.IsAnonymousUser(user) {
		return serializer.NewError(serializer.CodeAnonymouseAccessDenied, "Login required to save a share", nil)
	}

	shareID, err := dep.HashIDEncoder().Decode(service.ID, hashid.ShareID)
	if err != nil {
		return serializer.NewError(serializer.CodeParamErr, "Invalid share ID", err)
	}

	ctx := context.WithValue(c, inventory.LoadShareFile{}, true)
	ctx = context.WithValue(ctx, inventory.LoadShareUser{}, true)
	share, err := dep.ShareClient().GetByID(ctx, shareID)
	if err != nil {
		return serializer.NewError(serializer.CodeNotFound, "share not found", err)
	}

	// Password check, same as share visiting.
	if share.Password != "" && service.Password != share.Password && share.Edges.User.ID != user.ID {
		return serializer.NewError(serializer.CodeNoPermissionErr, "Incorrect share password", nil)
	}

	dbClient := dep.DBClient()

	// Idempotent: skip if a shortcut to this share already exists.
	existing, err := dbClient.File.Query().
		Where(
			entfile.IsSymbolic(true),
			entfile.OwnerIDEQ(user.ID),
			entfile.FileChildrenEQ(share.Edges.File.ID),
		).
		First(c)
	if err != nil && !ent.IsNotFound(err) {
		return serializer.NewError(serializer.CodeDBError, "Failed to check existing shortcuts", err)
	}
	if existing != nil {
		return nil
	}

	creator := dbClient.File.Create().
		SetName(share.Edges.File.Name).
		SetType(share.Edges.File.Type).
		SetIsSymbolic(true).
		SetOwnerID(user.ID).
		SetFileChildren(share.Edges.File.ID)
	if _, err := creator.Save(c); err != nil {
		return serializer.NewError(serializer.CodeDBError, "Failed to save shortcut", err)
	}

	return nil
}

func DeleteShare(c *gin.Context, shareId int) error {
	dep := dependency.FromContext(c)
	user := inventory.UserFromContext(c)
	shareClient := dep.ShareClient()

	ctx := context.WithValue(c, inventory.LoadShareFile{}, true)
	var (
		share *ent.Share
		err   error
	)
	if user.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)) {
		share, err = shareClient.GetByID(ctx, shareId)
	} else {
		share, err = shareClient.GetByIDUser(ctx, shareId, user.ID)
	}
	if err != nil {
		return serializer.NewError(serializer.CodeNotFound, "share not found", err)
	}

	if err := shareClient.Delete(c, share.ID); err != nil {
		return serializer.NewError(serializer.CodeDBError, "Failed to delete share", err)
	}

	shareName := ""
	if share.Edges.File != nil {
		shareName = share.Edges.File.Name
	}
	explorer.WriteAudit(c, eventtype.DeleteShare, "share", shareName, nil)
	return nil
}
