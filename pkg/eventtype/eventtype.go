// Package eventtype defines the site-wide audit event types, aligned 1:1
// with Cloudreve Pro's event system so records and settings stay portable.
package eventtype

// EventType is the numeric audit event type.
type EventType int

// Event types (identical numeric values as Pro).
const (
	ServerStart            EventType = 0
	UserSignup             EventType = 1
	EmailSent              EventType = 2
	UserActivated          EventType = 3
	UserLoginFailed        EventType = 4
	UserLogin              EventType = 5
	UserTokenRefresh       EventType = 6
	FileCreate             EventType = 7
	FileRename             EventType = 8
	SetFilePermission      EventType = 9
	EntityUploaded         EventType = 10
	EntityDownloaded       EventType = 11
	CopyFrom               EventType = 12
	CopyTo                 EventType = 13
	MoveTo                 EventType = 14
	DeleteFile             EventType = 15
	MoveToTrash            EventType = 16
	Share                  EventType = 17
	ShareLinkViewed        EventType = 18
	SetCurrentVersion      EventType = 19
	DeleteVersion          EventType = 20
	ThumbGenerated         EventType = 21
	LivePhotoUploaded      EventType = 22
	UpdateMetadata         EventType = 23
	EditShare              EventType = 24
	DeleteShare            EventType = 25
	Mount                  EventType = 26
	Relocate               EventType = 27
	CreateArchive          EventType = 28
	ExtractArchive         EventType = 29
	WebdavLoginFailed      EventType = 30
	WebdavAccountCreate    EventType = 31
	WebdavAccountUpdate    EventType = 32
	WebdavAccountDelete    EventType = 33
	PaymentCreated         EventType = 34
	PointsChange           EventType = 35
	PaymentPaid            EventType = 36
	PaymentFulfilled       EventType = 37
	PaymentFulfillFailed   EventType = 38
	StorageAdded           EventType = 39
	GroupChanged           EventType = 40
	UserExceedQuotaNotified EventType = 41
	UserChanged            EventType = 42
	GetDirectLink          EventType = 43
	LinkAccount            EventType = 44
	UnlinkAccount          EventType = 45
	ChangeNick             EventType = 46
	ChangeAvatar           EventType = 47
	MembershipUnsubscribe  EventType = 48
	ChangePassword         EventType = 49
	Enable2FA              EventType = 50
	Disable2FA             EventType = 51
	AddPasskey             EventType = 52
	RemovePasskey          EventType = 53
	RedeemGiftCode         EventType = 54
	FileImported           EventType = 55
	UpdateView             EventType = 56
	DeleteDirectLink       EventType = 57
	ReportAbuse            EventType = 58
	OauthGrantCreate       EventType = 59
	OauthTokenExchange     EventType = 60
	OauthGrantRevoke       EventType = 61
)

// names maps event type to its canonical Pro name.
var names = map[EventType]string{
	ServerStart: "server_start", UserSignup: "user_signup", EmailSent: "email_sent",
	UserActivated: "user_activated", UserLoginFailed: "user_login_failed",
	UserLogin: "user_login", UserTokenRefresh: "user_token_refresh",
	FileCreate: "file_create", FileRename: "file_rename",
	SetFilePermission: "set_file_permission", EntityUploaded: "entity_uploaded",
	EntityDownloaded: "entity_downloaded", CopyFrom: "copy_from", CopyTo: "copy_to",
	MoveTo: "move_to", DeleteFile: "delete_file", MoveToTrash: "move_to_trash",
	Share: "share", ShareLinkViewed: "share_link_viewed",
	SetCurrentVersion: "set_current_version", DeleteVersion: "delete_version",
	ThumbGenerated: "thumb_generated", LivePhotoUploaded: "live_photo_uploaded",
	UpdateMetadata: "update_metadata", EditShare: "edit_share", DeleteShare: "delete_share",
	Mount: "mount", Relocate: "relocate", CreateArchive: "create_archive",
	ExtractArchive: "extract_archive", WebdavLoginFailed: "webdav_login_failed",
	WebdavAccountCreate: "webdav_account_create", WebdavAccountUpdate: "webdav_account_update",
	WebdavAccountDelete: "webdav_account_delete", PaymentCreated: "payment_created",
	PointsChange: "points_change", PaymentPaid: "payment_paid",
	PaymentFulfilled: "payment_fulfilled", PaymentFulfillFailed: "payment_fulfill_failed",
	StorageAdded: "storage_added", GroupChanged: "group_changed",
	UserExceedQuotaNotified: "user_exceed_quota_notified", UserChanged: "user_changed",
	GetDirectLink: "get_direct_link", LinkAccount: "link_account",
	UnlinkAccount: "unlink_account", ChangeNick: "change_nick", ChangeAvatar: "change_avatar",
	MembershipUnsubscribe: "membership_unsubscribe", ChangePassword: "change_password",
	Enable2FA: "enable_2fa", Disable2FA: "disable_2fa", AddPasskey: "add_passkey",
	RemovePasskey: "remove_passkey", RedeemGiftCode: "redeem_gift_code",
	FileImported: "file_imported", UpdateView: "update_view",
	DeleteDirectLink: "delete_direct_link", ReportAbuse: "report_abuse",
	OauthGrantCreate: "oauth_grant_create", OauthTokenExchange: "oauth_token_exchange",
	OauthGrantRevoke: "oauth_grant_revoke",
}

// Name returns the canonical event name for a type.
func (t EventType) Name() string {
	if n, ok := names[t]; ok {
		return n
	}
	return "unknown"
}

// FromName resolves a canonical event name to its type.
func FromName(name string) (EventType, bool) {
	for t, n := range names {
		if n == name {
			return t, true
		}
	}
	return 0, false
}

// Category groups event types for settings toggles.
func (t EventType) Category() string {
	switch t {
	case ServerStart, FileImported, EmailSent:
		return "system"
	case UserSignup, UserActivated, UserLoginFailed, UserLogin, UserTokenRefresh,
		ChangeNick, ChangeAvatar, ChangePassword, Enable2FA, Disable2FA,
		AddPasskey, RemovePasskey, GroupChanged, UserChanged, UserExceedQuotaNotified:
		return "user"
	case FileCreate, FileRename, SetFilePermission, EntityUploaded, EntityDownloaded,
		CopyFrom, CopyTo, MoveTo, DeleteFile, MoveToTrash, SetCurrentVersion,
		DeleteVersion, ThumbGenerated, LivePhotoUploaded, UpdateMetadata,
		GetDirectLink, DeleteDirectLink, Relocate, CreateArchive, ExtractArchive:
		return "file"
	case Share, ShareLinkViewed, EditShare, DeleteShare, ReportAbuse:
		return "share"
	case Mount, WebdavLoginFailed, WebdavAccountCreate, WebdavAccountUpdate, WebdavAccountDelete:
		return "filesystem"
	case PaymentCreated, PointsChange, PaymentPaid, PaymentFulfilled,
		PaymentFulfillFailed, StorageAdded, RedeemGiftCode, MembershipUnsubscribe:
		return "payment"
	default:
		return "other"
	}
}
