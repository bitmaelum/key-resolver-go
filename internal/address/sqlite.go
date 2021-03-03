// Copyright (c) 2020 BitMaelum Authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package address

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"database/sql"

	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

type SqliteDbResolver struct {
	conn      *sql.DB
	dsn       string
	TableName string
	TimeNow   time.Time
}

// NewDynamoDBResolver returns a new resolver based on DynamoDB
func NewSqliteResolver(dsn string) Repository {
	if !strings.HasPrefix(dsn, "file:") {
		if dsn == ":memory:" {
			dsn = "file::memory:?mode=memory"
		} else {
			dsn = fmt.Sprintf("file:%s?cache=shared&mode=rwc", dsn)
		}
	}

	conn, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil
	}

	db := &SqliteDbResolver{
		conn:    conn,
		dsn:     dsn,
		TimeNow: time.Now(),
	}

	_, err = db.conn.Exec("CREATE TABLE IF NOT EXISTS mock_address (hash VARCHAR(64) PRIMARY KEY, pubkey TEXT, routing_id VARCHAR(64), proof TEXT, serial INTEGER, deleted INTEGER, deleted_at INTEGER)")
	if err != nil {
		return nil
	}

	_, err = db.conn.Exec("CREATE TABLE IF NOT EXISTS mock_history (hash VARCHAR(64), fingerprint VARCHAR(64), status INTEGER, PRIMARY KEY (hash, fingerprint))")
	if err != nil {
		return nil
	}

	return db
}

func (r *SqliteDbResolver) Update(info *ResolveInfoType, routing string, publicKey *bmcrypto.PubKey) (bool, error) {
	newSerial := strconv.FormatUint(uint64(r.TimeNow.UnixNano()), 10)

	_ = r.updateKeyHistory(info.Hash, publicKey.Fingerprint(), KSNormal)

	st, err := r.conn.Prepare("UPDATE mock_address SET routing_id=?, pubkey=?, serial=? WHERE hash=? AND serial=?")
	if err != nil {
		return false, err
	}

	res, err := st.Exec(routing, publicKey.String(), newSerial, info.Hash, info.Serial)
	if err != nil {
		return false, err
	}

	count, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if count == 0 {
		return false, errors.New("not updated")
	}
	return true, nil
}

func (r *SqliteDbResolver) Create(hash, routing string, publicKey *bmcrypto.PubKey, proof string) (bool, error) {
	serial := strconv.FormatUint(uint64(r.TimeNow.UnixNano()), 10)

	_ = r.updateKeyHistory(hash, publicKey.Fingerprint(), KSNormal)

	res, err := r.conn.Exec("INSERT INTO mock_address VALUES (?, ?, ?, ?, ?, 0, 0)", hash, publicKey.String(), routing, proof, serial)
	if err != nil {
		return false, err
	}

	count, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if count == 0 {
		return false, errors.New("not created")
	}
	return true, nil
}

func (r *SqliteDbResolver) Get(hash string) (*ResolveInfoType, error) {
	var (
		h   string
		pk  string
		rt  string
		pow string
		sn  uint64
		d   bool
		da  int64
	)

	err := r.conn.QueryRow("SELECT hash, pubkey, routing_id, proof, serial, deleted, deleted_at FROM mock_address WHERE hash LIKE ?", hash).Scan(&h, &pk, &rt, &pow, &sn, &d, &da)
	if err != nil {
		return nil, ErrNotFound
	}

	return &ResolveInfoType{
		Hash:      h,
		RoutingID: rt,
		PubKey:    pk,
		Proof:     pow,
		Serial:    sn,
		Deleted:   d,
		DeletedAt: time.Unix(da, 0),
	}, nil
}

func (r *SqliteDbResolver) Delete(hash string) (bool, error) {
	res, err := r.conn.Exec("DELETE FROM mock_address WHERE hash LIKE ?", hash)
	if err != nil {
		return false, err
	}

	count, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if count == 0 {
		return false, errors.New("not deleted")
	}
	return true, nil
}

func (r *SqliteDbResolver) SoftDelete(hash string) (bool, error) {
	st, err := r.conn.Prepare("UPDATE mock_address SET deleted=1, deleted_at=? WHERE hash=?")
	if err != nil {
		return false, err
	}

	dt := time.Now().Unix()
	res, err := st.Exec(dt, hash)
	if err != nil {
		return false, err
	}

	count, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if count == 0 {
		return false, errors.New("not soft deleted")
	}
	return true, nil
}

func (r *SqliteDbResolver) SoftUndelete(hash string) (bool, error) {
	st, err := r.conn.Prepare("UPDATE mock_address SET deleted=0, deleted_at=0 WHERE hash=?")
	if err != nil {
		return false, err
	}

	res, err := st.Exec(hash)
	if err != nil {
		return false, err
	}

	count, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if count == 0 {
		return false, errors.New("not soft undeleted")
	}
	return true, nil
}

func (r *SqliteDbResolver) CheckKey(hash string, fingerprint string) (KeyStatus, error) {
	var ks *KeyStatus

	err := r.conn.QueryRow("SELECT status FROM mock_history WHERE hash LIKE ? AND fingerprint LIKE ?", hash, fingerprint).Scan(&ks)
	if err != nil {
		return KSNormal, ErrNotFound
	}

	return *ks, nil
}

func (r *SqliteDbResolver) updateKeyHistory(hash string, fingerprint string, status KeyStatus) error {
	_, err := r.conn.Exec("INSERT OR REPLACE INTO mock_history VALUES (?, ?, ?)", hash, fingerprint, status)

	return err
}

func (r *SqliteDbResolver) SetKeyStatus(hash string, fingerprint string, status KeyStatus) error {
	return r.updateKeyHistory(hash, fingerprint, status)
}
