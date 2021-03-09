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
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
)

// ResolveInfoType returns information found in the resolver repository
type ResolveInfoType struct {
	Hash      string
	RoutingID string
	PubKey    string
	Proof     string
	Serial    uint64
	Deleted   bool
	DeletedAt time.Time
}

type KeyStatus int

const (
	KSNormal      KeyStatus = iota + 1 // Regular key, just rotated
	KSCompromised                      // Key was compromised
)

var keyStatusMap = map[KeyStatus]string{
	KSNormal:      "normal",
	KSCompromised: "compromised",
}

func (k KeyStatus) ToString() string {
	return keyStatusMap[k]
}

func StringToKeyStatus(s string) (KeyStatus, error) {
	for i := range keyStatusMap {
		if keyStatusMap[i] == s {
			return i, nil
		}
	}

	return 0, errors.New("keystatus not found")
}

// Repository to resolve records
type Repository interface {
	// Retrieve from hash
	Get(hash string) (*ResolveInfoType, error)
	// Create a new entry
	Create(hash, routing string, publicKey *bmcrypto.PubKey, proof string) (bool, error)
	// Update an existing entry
	Update(info *ResolveInfoType, routing string, publicKey *bmcrypto.PubKey) (bool, error)
	// Softdelete an entry
	SoftDelete(hash string) (bool, error)
	// Undelete a softdeleted entry
	SoftUndelete(hash string) (bool, error)
	// Remove the entry completely (destructive)
	Delete(hash string) (bool, error)

	// Get the status of this (old) key
	GetKeyStatus(hash string, fingerprint string) (KeyStatus, error)
	// Set the given key status
	SetKeyStatus(hash string, fingerprint string, status KeyStatus) error
}

var resolver Repository

// GetResolveRepository returns a new repository based on DynamoDB
func GetResolveRepository() Repository {
	if resolver != nil {
		return resolver
	}

	if os.Getenv("USE_BOLT") == "1" {
		resolver = NewBoltResolver()
		return resolver
	}

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	resolver = NewDynamoDBResolver(dynamodb.New(sess), os.Getenv("ADDRESS_TABLE_NAME"), os.Getenv("HISTORY_TABLE_NAME"))
	return resolver
}

// Sets the default repository for resolving. Can be used to override for mocking/testing purposes
func SetDefaultRepository(r Repository) {
	resolver = r
}
