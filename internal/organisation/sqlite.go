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

package organisation

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"database/sql"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

type SqliteDbResolver struct {
	conn    *sql.DB
	dsn     string
	TimeNow time.Time
}

// NewDynamoDBResolver returns a new resolver based on DynamoDB
func NewSqliteResolver(dsn string) *SqliteDbResolver {
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

	_, _ = db.conn.Exec("CREATE TABLE IF NOT EXISTS mock_organisation (hash VARCHAR(64) PRIMARY KEY, proof TEXT, validations TEXT, pubkey TEXT, serial INTEGER)")
	return db
}

func (r *SqliteDbResolver) Update(info *ResolveInfoType, publicKey, proof string, validations []string) (bool, error) {
	newSerial := strconv.FormatUint(uint64(r.TimeNow.UnixNano()), 10)


	st, err := r.conn.Prepare("UPDATE mock_organisation SET pubkey=?, validations=?, proof=?, serial=? WHERE hash=? AND serial=?")
	if err != nil {
		return false, err
	}

	b, err := json.Marshal(validations)
	if err != nil {
		return false, err
	}

	res, err := st.Exec(publicKey, string(b), proof, newSerial, info.Hash, info.Serial)
	if err != nil {
		return false, err
	}

	count, err := res.RowsAffected()
	return count != 0, err
}

func (r *SqliteDbResolver) Create(hash, publicKey, proof string, validations []string) (bool, error) {
	newSerial := strconv.FormatUint(uint64(r.TimeNow.UnixNano()), 10)

	b, err := json.Marshal(validations)
	if err != nil {
		return false, err
	}

	res, err := r.conn.Exec("INSERT INTO mock_organisation VALUES (?, ?, ?, ?, ?)", hash, proof, string(b), publicKey, newSerial)
	if err != nil {
		return false, err
	}

	count, err := res.RowsAffected()
	return count != 0, err
}

func (r *SqliteDbResolver) Get(hash string) (*ResolveInfoType, error) {
	var (
		h   string
		pk  string
		pow string
		sn  uint64
		v   []byte
	)

	query := fmt.Sprintf("SELECT hash, pubkey, proof, validations, serial FROM mock_organisation WHERE hash LIKE ?")
	err := r.conn.QueryRow(query, hash).Scan(&h, &pk, &pow, &v, &sn)
	if err != nil {
		return nil, ErrNotFound
	}

	var val []string
	err = json.Unmarshal(v, &val)
	if err != nil {
		return nil, err
	}

	return &ResolveInfoType{
		Hash:        h,
		PubKey:      pk,
		Proof:       pow,
		Validations: val,
		Serial:      sn,
	}, nil
}

func (r *SqliteDbResolver) Delete(hash string) (bool, error) {
	res, err := r.conn.Exec("DELETE FROM mock_organisation WHERE hash LIKE ?", hash)
	if err != nil {
		return false, err
	}

	count, err := res.RowsAffected()
	return count != 0, err
}
