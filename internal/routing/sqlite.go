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

package routing

import (
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

	_, _ = db.conn.Exec("CREATE TABLE IF NOT EXISTS mock_routing (routing_id VARCHAR(64) PRIMARY KEY, pubkey TEXT, routing TEXT, serial INTEGER)")
	return db
}

func (r *SqliteDbResolver) Update(info *ResolveInfoType, routing, publicKey string) (bool, error) {
	newSerial := strconv.FormatUint(uint64(r.TimeNow.UnixNano()), 10)

	st, err := r.conn.Prepare("UPDATE mock_routing SET pubkey=?, routing=?, serial=? WHERE routing_id=? AND serial=?")
	if err != nil {
		return false, err
	}

	res, err := st.Exec(publicKey, routing, newSerial, info.Hash, info.Serial)
	if err != nil {
		return false, err
	}

	count, err := res.RowsAffected()
	return count != 0, err
}

func (r *SqliteDbResolver) Create(hash, routing, publicKey string) (bool, error) {
	newSerial := strconv.FormatUint(uint64(r.TimeNow.UnixNano()), 10)

	res, err := r.conn.Exec("INSERT INTO mock_routing VALUES (?, ?, ?, ?)", hash, publicKey, routing, newSerial)
	if err != nil {
		return false, err
	}

	count, err := res.RowsAffected()
	return count != 0, err
}

func (r *SqliteDbResolver) Get(hash string) (*ResolveInfoType, error) {
	var (
		h  string
		pk string
		rt string
		sn uint64
	)

	err := r.conn.QueryRow("SELECT routing_id, pubkey, routing, serial FROM mock_routing WHERE routing_id LIKE ?", hash).Scan(&h, &pk, &rt, &sn)
	if err != nil {
		return nil, ErrNotFound
	}

	return &ResolveInfoType{
		Hash:    h,
		PubKey:  pk,
		Routing: rt,
		Serial:  sn,
	}, nil
}

func (r *SqliteDbResolver) Delete(hash string) (bool, error) {
	res, err := r.conn.Exec("DELETE FROM mock_routing WHERE routing_id LIKE ?", hash)
	if err != nil {
		return false, err
	}

	count, err := res.RowsAffected()
	return count != 0, err
}
