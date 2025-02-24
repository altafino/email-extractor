package tracking

import (
	"context"
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

type MessageIdentifier struct {
	AccountID string
	MessageID string
	From      string
	Subject   string
	Date      time.Time
	Hash      string // Computed from combination of fields
}

type Tracker interface {
	IsProcessed(ctx context.Context, msg MessageIdentifier) (bool, error)
	MarkProcessed(ctx context.Context, msg MessageIdentifier) error
	Cleanup(ctx context.Context) error
}

type SQLiteTracker struct {
	db              *sql.DB
	retentionPeriod time.Duration
}

func NewSQLiteTracker(dbPath string, retentionDays int) (*SQLiteTracker, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	// Create table if not exists
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS processed_messages (
			account_id TEXT,
			message_hash TEXT,
			processed_at TIMESTAMP,
			message_id TEXT,
			from_address TEXT,
			subject TEXT,
			message_date TIMESTAMP,
			PRIMARY KEY (account_id, message_hash)
		)
	`)
	if err != nil {
		return nil, err
	}

	return &SQLiteTracker{
		db:              db,
		retentionPeriod: time.Duration(retentionDays) * 24 * time.Hour,
	}, nil
}

func (t *SQLiteTracker) IsProcessed(ctx context.Context, msg MessageIdentifier) (bool, error) {
	var exists bool
	err := t.db.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM processed_messages WHERE account_id = ? AND message_hash = ?)",
		msg.AccountID, msg.Hash,
	).Scan(&exists)
	return exists, err
}

func (t *SQLiteTracker) MarkProcessed(ctx context.Context, msg MessageIdentifier) error {
	_, err := t.db.ExecContext(ctx,
		`INSERT INTO processed_messages 
		(account_id, message_hash, processed_at, message_id, from_address, subject, message_date)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		msg.AccountID,
		msg.Hash,
		time.Now().UTC(),
		msg.MessageID,
		msg.From,
		msg.Subject,
		msg.Date,
	)
	return err
}

func (t *SQLiteTracker) Cleanup(ctx context.Context) error {
	cutoff := time.Now().Add(-t.retentionPeriod)
	_, err := t.db.ExecContext(ctx,
		"DELETE FROM processed_messages WHERE processed_at < ?",
		cutoff,
	)
	return err
}
