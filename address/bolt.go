package address

import (
	"encoding/json"
	"log"
	"time"

	"github.com/boltdb/bolt"
)

type boltResolver struct {
	client     *bolt.DB
	bucketName string
}

// NewBoltResolver returns a new resolver based on BoltDB
func NewBoltResolver(p string) Repository {
	db, err := bolt.Open(p, 0600, nil)
	if err != nil {
		log.Fatal(err)
	}

	return &boltResolver{
		client:     db,
		bucketName: "address",
	}
}

func (b boltResolver) Get(hash string) (*ResolveInfoType, error) {
	rec := &ResolveInfoType{}

	err := b.client.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(b.bucketName))
		if bucket == nil {
			return ErrNotFound
		}

		data := bucket.Get([]byte(hash))
		if data == nil {
			return ErrNotFound
		}

		return json.Unmarshal(data, &rec)
	})

	if err != nil {
		return nil, err
	}

	return rec, nil
}

func (b boltResolver) Create(hash, routing, publicKey, proof string) (bool, error) {
	err := b.client.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(b.bucketName))
		if err != nil {
			return err
		}

		rec := &ResolveInfoType{
			Hash:      hash,
			RoutingID: routing,
			PubKey:    publicKey,
			Proof:     proof,
			Serial:    uint64(time.Now().UnixNano()),
		}
		buf, err := json.Marshal(rec)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(hash), buf)
	})

	if err != nil {
		return false, err
	}

	return true, nil
}

func (b boltResolver) Update(info *ResolveInfoType, routing, publicKey string) (bool, error) {
	return b.Create(info.Hash, routing, publicKey, info.Proof)
}

func (b boltResolver) Delete(hash string) (bool, error) {
	err := b.client.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(b.bucketName))
		if bucket == nil {
			return nil
		}

		return bucket.Delete([]byte(hash))
	})

	if err != nil {
		return false, err
	}

	return true, nil
}
