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
	"encoding/json"
	"time"

	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/key-resolver-go/internal"
	bolt "go.etcd.io/bbolt"
)

type boltResolver struct {
	client     *bolt.DB
	bucketName []byte
}

// NewBoltResolver returns a new resolver based on BoltDB
func NewBoltResolver() Repository {
	return &boltResolver{
		client:     internal.GetBoltDb(),
		bucketName: []byte("address"),
	}
}

func (b boltResolver) Get(hash string) (*ResolveInfoType, error) {
	rec := &ResolveInfoType{}

	err := b.client.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(b.bucketName)
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

func (b boltResolver) Create(hash, routing string, publicKey *bmcrypto.PubKey, proof string) (bool, error) {
	err := b.client.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(b.bucketName)
		if err != nil {
			return err
		}

		rec := &ResolveInfoType{
			Hash:      hash,
			RoutingID: routing,
			PubKey:    publicKey.String(),
			Proof:     proof,
			Serial:    uint64(time.Now().UnixNano()),
			Deleted:   false,
			DeletedAt: time.Time{},
		}
		buf, err := json.Marshal(rec)
		if err != nil {
			return err
		}

		err = bucket.Put([]byte(hash), buf)
		if err != nil {
			return err
		}

		// Store in history
		bucket, err = tx.CreateBucketIfNotExists([]byte(hash + "fingerprints"))
		if err != nil {
			return err
		}

		b, err := json.Marshal(KSNormal)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(publicKey.Fingerprint()), b)
	})

	if err != nil {
		return false, err
	}

	return true, nil
}

func (b boltResolver) Update(info *ResolveInfoType, routing string, publicKey *bmcrypto.PubKey) (bool, error) {
	err := b.client.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(b.bucketName)
		if bucket == nil {
			return nil
		}

		rec, err := getFromBucket(bucket, info.Hash)
		if err != nil {
			return ErrNotFound
		}

		if rec.Serial != info.Serial {
			return ErrNotFound
		}

		rec.RoutingID = routing
		rec.PubKey = publicKey.String()
		buf, err := json.Marshal(rec)
		if err != nil {
			return err
		}

		// Store in history (overwrite if already exists)
		b, err := json.Marshal(KSNormal)
		if err != nil {
			return err
		}
		err = bucket.Put([]byte(info.Hash+publicKey.Fingerprint()), b)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(info.Hash), buf)
	})

	if err != nil {
		return false, err
	}

	return true, nil
}

func (b boltResolver) SoftDelete(hash string) (bool, error) {
	err := b.client.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(b.bucketName)
		if bucket == nil {
			return nil
		}

		rec, err := getFromBucket(bucket, hash)
		if err != nil {
			return ErrNotFound
		}

		// make record deleted
		rec.Deleted = true
		rec.DeletedAt = time.Now()

		// Store
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

func (b boltResolver) SoftUndelete(hash string) (bool, error) {
	err := b.client.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(b.bucketName)
		if bucket == nil {
			return nil
		}

		rec, err := getFromBucket(bucket, hash)
		if err != nil {
			return ErrNotFound
		}

		// undelete
		rec.Deleted = false
		rec.DeletedAt = time.Time{}

		// Store
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

func (b boltResolver) Delete(hash string) (bool, error) {
	err := b.client.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(b.bucketName)
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

func (b boltResolver) GetKeyStatus(hash string, fingerprint string) (KeyStatus, error) {
	var ks KeyStatus

	err := b.client.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(hash + "fingerprints"))
		if bucket == nil {
			return ErrNotFound
		}

		result := bucket.Get([]byte(fingerprint))
		if result == nil {
			return ErrNotFound
		}

		err := json.Unmarshal(result, &ks)
		if err != nil {
			return err
		}

		return nil
	})

	return ks, err
}

func (b boltResolver) SetKeyStatus(hash string, fingerprint string, status KeyStatus) error {
	return b.client.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(hash + "fingerprints"))
		if bucket == nil {
			return nil
		}

		// Check if hash+fingerprint exist
		result := bucket.Get([]byte(fingerprint))
		if result == nil {
			return ErrNotFound
		}

		b, err := json.Marshal(status)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(fingerprint), b)
	})
}

func getFromBucket(bucket *bolt.Bucket, hash string) (*ResolveInfoType, error) {
	data := bucket.Get([]byte(hash))
	if data == nil {
		return nil, ErrNotFound
	}

	rec := &ResolveInfoType{}
	err := json.Unmarshal(data, &rec)
	if err != nil {
		return nil, ErrNotFound
	}

	return rec, nil
}
