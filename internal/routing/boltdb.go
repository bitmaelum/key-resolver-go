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
		bucketName: "routing",
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

func (b boltResolver) Create(hash, routing, publicKey string) (bool, error) {
	err := b.client.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(b.bucketName))
		if err != nil {
			return err
		}

		rec := &ResolveInfoType{
			Hash:    hash,
			Routing: routing,
			PubKey:  publicKey,
			Serial:  uint64(time.Now().UnixNano()),
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
	return b.Create(info.Hash, routing, publicKey)
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
