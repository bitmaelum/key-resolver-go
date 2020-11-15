package internal

import (
	"log"
	"os"

	"github.com/boltdb/bolt"
)

var boltdb *bolt.DB

// GetBoltDb opens a generic bolt-db handle. This is because we use the same bolt-db file for multiple repositories and
// otherwise it cannot open the file because another repository already has it open
func GetBoltDb() *bolt.DB {
	if boltdb != nil {
		return boltdb
	}

	var err error
	p := os.Getenv("BOLT_DB_FILE")
	boltdb, err = bolt.Open(p, 0600, nil)
	if err != nil {
		log.Fatal(err)
	}

	return boltdb
}
