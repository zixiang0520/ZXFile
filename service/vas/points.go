package vas

import (
	"context"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/pointsledger"
	"fmt"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	inventorytypes "github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/eventtype"
)

// auditWriter writes an audit log entry with an ent client (usable outside
// of a request context).
func auditWriter(ctx context.Context, db *ent.Client, userID int, email string,
	ev eventtype.EventType, objType, objName string, content map[string]interface{}) {
	if content == nil {
		content = map[string]interface{}{}
	}
	creator := db.AuditLog.Create().
		SetType(int(ev)).
		SetAction(ev.Name()).
		SetObjectType(objType).
		SetObjectName(objName).
		SetContent(content).
		SetIP("")
	if userID > 0 {
		creator = creator.SetUserID(userID).SetUserEmail(email)
	}
	if _, err := creator.Save(ctx); err != nil {
		_ = err
	}
}

// GetPointsBalance returns the user's points balance (sum of the ledger).
func GetPointsBalance(ctx context.Context, db *ent.Client, userID int) int64 {
	rows, err := db.PointsLedger.Query().
		Where(pointsledger.UserIDEQ(userID)).
		Select(pointsledger.FieldDelta).
		All(ctx)
	if err != nil {
		return 0
	}
	var sum int64
	for _, r := range rows {
		sum += r.Delta
	}
	return sum
}

// GainPoints adds points to a user and records the change.
func GainPoints(ctx context.Context, db *ent.Client, userID int, amount int64, reason, note string, paymentID int) (int64, error) {
	if amount <= 0 {
		return GetPointsBalance(ctx, db, userID), nil
	}
	return changePoints(ctx, db, userID, amount, reason, note, paymentID)
}

// DeductPoints spends points from a user's balance.
func DeductPoints(ctx context.Context, db *ent.Client, userID int, amount int64, reason, note string, paymentID int) (int64, error) {
	return changePoints(ctx, db, userID, -amount, reason, note, paymentID)
}

func changePoints(ctx context.Context, db *ent.Client, userID int, delta int64, reason, note string, paymentID int) (int64, error) {
	balance := GetPointsBalance(ctx, db, userID)
	creator := db.PointsLedger.Create().
		SetUserID(userID).
		SetDelta(delta).
		SetBalanceAfter(balance + delta).
		SetReason(reason).
		SetNote(note)
	if paymentID > 0 {
		creator = creator.SetPaymentID(paymentID)
	}
	if _, err := creator.Save(ctx); err != nil {
		return balance, err
	}
	return balance + delta, nil
}

// addExtraStorage appends purchased capacity to the user's settings
// (extra_storage, in bytes).
func addExtraStorage(ctx context.Context, db *ent.Client, userID int, bytes int64) error {
	u, err := db.User.Query().Where(entuser.IDEQ(userID)).First(ctx)
	if err != nil {
		return fmt.Errorf("load user #%d: %w", userID, err)
	}
	settings := u.Settings
	if settings == nil {
		settings = &inventorytypes.UserSetting{}
	}
	settings.ExtraStorage += bytes
	return db.User.UpdateOneID(userID).SetSettings(settings).Exec(ctx)
}

// loadExtraStorage reads the user's purchased extra capacity.
func loadExtraStorage(ctx context.Context, db *ent.Client, userID int) int64 {
	u, err := db.User.Query().Where(entuser.IDEQ(userID)).First(ctx)
	if err != nil || u.Settings == nil {
		return 0
	}
	return u.Settings.ExtraStorage
}

// GainPointsTx adds points within an existing transaction.
func GainPointsTx(ctx context.Context, tx *ent.Tx, userID int, amount int64, reason, note string) (int64, error) {
	if amount <= 0 {
		return 0, nil
	}
	creator := tx.PointsLedger.Create().
		SetUserID(userID).
		SetDelta(amount).
		SetBalanceAfter(GetPointsBalance(ctx, tx.Client(), userID) + amount).
		SetReason(reason).
		SetNote(note)
	if _, err := creator.Save(ctx); err != nil {
		return 0, err
	}
	return GetPointsBalance(ctx, tx.Client(), userID), nil
}
