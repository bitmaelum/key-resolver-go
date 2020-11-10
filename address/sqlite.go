package address

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"database/sql"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

type sqliteDbResolver struct {
	conn      *sql.DB
	dsn       string
	TableName string
}

// NewDynamoDBResolver returns a new resolver based on DynamoDB
func NewSqliteResolver(dsn, tableName string) Repository {
	if !strings.HasPrefix(dsn, "file:") {
		if dsn == ":memory:" {
			dsn = "file::memory:?mode=memory&cache=shared"
		} else {
			dsn = fmt.Sprintf("file:%s?cache=shared&mode=rwc", dsn)
		}
	}

	conn, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil
	}

	db := &sqliteDbResolver{
		conn:      conn,
		dsn:       dsn,
		TableName: tableName,
	}

	_, _ = db.conn.Query(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (hash VARCHAR(64) PRIMARY KEY, pubkey TEXT, routing_id VARCHAR(64), serial INT)", db.TableName))
	return db
}

func (r *sqliteDbResolver) Update(info *ResolveInfoType, routing, publicKey string) (bool, error) {
	serial := strconv.FormatUint(uint64(time.Now().UnixNano()), 10)

	query := fmt.Sprintf("UPDATE %s SET pubkey=?, proof=?, serial=? WHERE hash=? AND serial=?", r.TableName)
	st, err := r.conn.Prepare(query)
	if err != nil {
		return false, err
	}

	res, err := st.Exec(info.PubKey, info.Proof, serial, info.Hash, info.Serial)
	if err != nil {
		return false, err
	}

	numDeleted, err := res.RowsAffected()
	return numDeleted != 0, err
}

func (r *sqliteDbResolver) Create(hash, routing, publicKey, proof string) (bool, error) {
	serial := strconv.FormatUint(uint64(time.Now().UnixNano()), 10)

	query := fmt.Sprintf("INSERTO INTO %s VALUES (hash, pubkey, proof, serial)", r.TableName)
	st, err := r.conn.Prepare(query)
	if err != nil {
		return false, err
	}

	_, err = st.Exec(hash, publicKey, proof, serial)
	return err != nil, err
}

func (r *sqliteDbResolver) Get(hash string) (*ResolveInfoType, error) {
	var (
		h   string
		pk  string
		pow string
		sn  uint64
	)

	query := fmt.Sprintf("SELECT hash, pubkey, proof, serial FROM %s WHERE hash LIKE ?", r.TableName)
	err := r.conn.QueryRow(query, hash).Scan(&h, &pk, &pow, &sn)
	if err != nil {
		return nil, ErrNotFound
	}

	return &ResolveInfoType{
		Hash:   h,
		PubKey: pk,
		Proof:  pow,
		Serial: sn,
	}, nil
}

func (r *sqliteDbResolver) Delete(hash string) (bool, error) {
	query := fmt.Sprintf("DELETE FROM %s WHERE hash LIKE ?", r.TableName)
	st, err := r.conn.Prepare(query)
	if err != nil {
		return false, err
	}

	res, err := st.Exec(hash)
	if err != nil {
		return false, err
	}

	numDeleted, err := res.RowsAffected()
	return numDeleted != 0, err
}
