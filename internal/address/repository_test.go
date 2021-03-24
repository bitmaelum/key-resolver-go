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
	"os"

	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	testing2 "github.com/bitmaelum/key-resolver-go/internal/testing"
	"github.com/stretchr/testify/assert"

	"testing"
)

func TestDynamoRepo(t *testing.T) {
	_ = os.Setenv("USE_BOLT", "0")
	_ = os.Setenv("ADDRESS_TABLE_NAME", "mock")
	SetDefaultRepository(nil)

	r := GetResolveRepository()
	assert.IsType(t, r, NewDynamoDBResolver(nil, "", ""))
}

func TestBoltResolverRepo(t *testing.T) {
	_ = os.Setenv("USE_BOLT", "1")
	_ = os.Setenv("BOLT_DB_FILE", "/tmp/mockdb.db")
	SetDefaultRepository(nil)

	r := GetResolveRepository()
	assert.IsType(t, r, NewBoltResolver())
}

func runRepositoryHistoryCheck(t *testing.T, db Repository) {
	h1 := hash.Hash("address1!")
	h2 := hash.Hash("address2!")

	_, pub1, _ := testing2.ReadTestKey("../../testdata/key-1.json")
	_, pub2, _ := testing2.ReadTestKey("../../testdata/key-2.json")
	_, pub3, _ := testing2.ReadTestKey("../../testdata/key-3.json")
	_, pub4, _ := testing2.ReadTestKey("../../testdata/key-4.json")

	ok, err := db.Create(h1.String(), "12345678", pub1, "proof", "")
	assert.NoError(t, err)
	assert.True(t, ok)

	// Correct key
	res, err := db.GetKeyStatus(h1.String(), pub1.Fingerprint())
	assert.NoError(t, err)
	assert.Equal(t, KSNormal, res)

	// Other key
	_, err = db.GetKeyStatus(h1.String(), pub2.Fingerprint())
	assert.Error(t, err)

	// Other account
	_, err = db.GetKeyStatus(h2.String(), pub1.Fingerprint())
	assert.Error(t, err)

	// update key
	info, _ := db.Get(h1.String())
	ok, err = db.Update(info, "12345678", pub2, "")
	assert.NoError(t, err)
	assert.True(t, ok)

	// Correct key
	res, err = db.GetKeyStatus(h1.String(), pub1.Fingerprint())
	assert.NoError(t, err)
	assert.Equal(t, KSNormal, res)

	// Other key is correct as well now
	res, err = db.GetKeyStatus(h1.String(), pub2.Fingerprint())
	assert.NoError(t, err)
	assert.Equal(t, KSNormal, res)

	// Other account still not the key
	_, err = db.GetKeyStatus(h2.String(), pub1.Fingerprint())
	assert.Error(t, err)

	// update key on other account
	ok, err = db.Create(h2.String(), "12345678", pub3, "proof", "")
	assert.NoError(t, err)
	assert.True(t, ok)

	// Correct key
	res, err = db.GetKeyStatus(h1.String(), pub1.Fingerprint())
	assert.NoError(t, err)
	assert.Equal(t, KSNormal, res)

	// Other key is correct as well now
	res, err = db.GetKeyStatus(h1.String(), pub2.Fingerprint())
	assert.NoError(t, err)
	assert.Equal(t, KSNormal, res)

	// Other account still not the key
	_, err = db.GetKeyStatus(h2.String(), pub1.Fingerprint())
	assert.Error(t, err)

	// Other account has other key
	res, err = db.GetKeyStatus(h2.String(), pub3.Fingerprint())
	assert.NoError(t, err)
	assert.Equal(t, KSNormal, res)

	// Update first key again
	info, _ = db.Get(h1.String())
	ok, err = db.Update(info, "12345678", pub4, "")
	assert.NoError(t, err)
	assert.True(t, ok)

	// Correct key
	res, err = db.GetKeyStatus(h1.String(), pub1.Fingerprint())
	assert.NoError(t, err)
	assert.Equal(t, KSNormal, res)

	// Other key is correct as well now
	res, err = db.GetKeyStatus(h1.String(), pub2.Fingerprint())
	assert.NoError(t, err)
	assert.Equal(t, KSNormal, res)

	// Pub3 is not here
	_, err = db.GetKeyStatus(h1.String(), pub3.Fingerprint())
	assert.Error(t, err)

	res, err = db.GetKeyStatus(h1.String(), pub4.Fingerprint())
	assert.NoError(t, err)
	assert.Equal(t, KSNormal, res)
}

func runRepositoryHistoryKeyStatus(t *testing.T, db Repository) {
	h1 := hash.Hash("address1!")

	_, pub1, _ := testing2.ReadTestKey("../../testdata/key-1.json")
	_, pub2, _ := testing2.ReadTestKey("../../testdata/key-2.json")

	ok, err := db.Create(h1.String(), "12345678", pub1, "proof", "")
	assert.NoError(t, err)
	assert.True(t, ok)

	// Correct key in normal state
	res, err := db.GetKeyStatus(h1.String(), pub1.Fingerprint())
	assert.NoError(t, err)
	assert.Equal(t, KSNormal, res)

	// Rotate key
	info, _ := db.Get(h1.String())
	ok, err = db.Update(info, "12345678", pub2, "")
	assert.NoError(t, err)
	assert.True(t, ok)

	// Set compromised key status of key 1
	err = db.SetKeyStatus(h1.String(), pub1.Fingerprint(), KSCompromised)
	assert.NoError(t, err)

	// First key is compromised
	res, err = db.GetKeyStatus(h1.String(), pub1.Fingerprint())
	assert.NoError(t, err)
	assert.Equal(t, KSCompromised, res)

	// Second key is normal
	res, err = db.GetKeyStatus(h1.String(), pub2.Fingerprint())
	assert.NoError(t, err)
	assert.Equal(t, KSNormal, res)

}

func runRepositoryCreateUpdateTest(t *testing.T, db Repository) {
	h1 := hash.Hash("address1!")
	h2 := hash.Hash("address2!")
	h3 := hash.Hash("address3!")

	_, pubkey, _ := bmcrypto.GenerateKeyPair("ed25519")

	// Create key
	ok, err := db.Create(h1.String(), "12345678", pubkey, "proof", "")
	assert.NoError(t, err)
	assert.True(t, ok)

	// Fetch unknown hash
	info, err := db.Get(h2.String())
	assert.Error(t, err)
	assert.Nil(t, info)

	// Fetch created hash
	info, err = db.Get(h1.String())
	assert.NoError(t, err)
	assert.Equal(t, "12345678", info.RoutingID)
	assert.Equal(t, h1.String(), info.Hash)
	assert.Equal(t, pubkey.String(), info.PubKey)
	assert.Equal(t, "proof", info.Proof)

	_, pubkey2, _ := bmcrypto.GenerateKeyPair("ed25519")

	// Update info
	ok, err = db.Update(info, "11112222", pubkey2, "")
	assert.NoError(t, err)
	assert.True(t, ok)

	// Fetch info
	info, err = db.Get(h1.String())
	assert.NoError(t, err)
	assert.Equal(t, "11112222", info.RoutingID)
	assert.Equal(t, h1.String(), info.Hash)
	assert.Equal(t, pubkey2.String(), info.PubKey)
	assert.Equal(t, "proof", info.Proof)

	_, pubkey3, _ := bmcrypto.GenerateKeyPair("ed25519")

	// Try and update with incorrect serial number
	info.Serial = 1234
	ok, err = db.Update(info, "88881111", pubkey3, "")
	assert.False(t, ok)
	assert.Error(t, err)

	// Read back unmodified info
	info, err = db.Get(h1.String())
	assert.NoError(t, err)
	assert.Equal(t, "11112222", info.RoutingID)
	assert.Equal(t, h1.String(), info.Hash)
	assert.Equal(t, pubkey2.String(), info.PubKey)
	assert.Equal(t, "proof", info.Proof)

	// Update with redir hash
	info, _ = db.Get(h1.String())
	ok, err = db.Update(info, "77772222", pubkey3, hash.New("foobar").String())
	assert.NoError(t, err)
	assert.True(t, ok)

	// Read back unmodified info
	info, err = db.Get(h1.String())
	assert.NoError(t, err)
	assert.Equal(t, "77772222", info.RoutingID)
	assert.Equal(t, h1.String(), info.Hash)
	assert.Equal(t, hash.New("foobar").String(), info.RedirHash)
	assert.Equal(t, pubkey3.String(), info.PubKey)

	// Create with redir hash
	ok, err = db.Create(h3.String(), "12345678", pubkey, "proof", hash.New("dest").String())
	assert.NoError(t, err)
	assert.True(t, ok)

	// Fetch created hash
	info, err = db.Get(h3.String())
	assert.NoError(t, err)
	assert.Equal(t, "12345678", info.RoutingID)
	assert.Equal(t, h3.String(), info.Hash)
	assert.Equal(t, hash.New("dest").String(), info.RedirHash)
	assert.Equal(t, pubkey.String(), info.PubKey)
	assert.Equal(t, "proof", info.Proof)
}

func runRepositoryDeletionTests(t *testing.T, db Repository) {
	h1 := hash.Hash("address1!")
	h2 := hash.Hash("address2!")

	_, pubkey, _ := bmcrypto.GenerateKeyPair("ed25519")

	// Create key
	ok, err := db.Create(h1.String(), "12345678", pubkey, "proof", "")
	assert.NoError(t, err)
	assert.True(t, ok)

	// Fetch created hash
	info, err := db.Get(h1.String())
	assert.NoError(t, err)
	assert.NotNil(t, info)

	// Try and softdelete unknown
	ok, err = db.SoftDelete(h2.String())
	assert.Error(t, err)
	assert.False(t, ok)

	// Softdelete known entry
	ok, err = db.SoftDelete(h1.String())
	assert.NoError(t, err)
	assert.True(t, ok)

	info, err = db.Get(h1.String())
	assert.NoError(t, err)
	assert.NotNil(t, info)

	// Softdelete again
	ok, err = db.SoftDelete(h1.String())
	assert.NoError(t, err)
	assert.True(t, ok)

	// Undelete unknown
	ok, err = db.SoftUndelete(h2.String())
	assert.Error(t, err)
	assert.False(t, ok)

	// undelete known
	ok, err = db.SoftUndelete(h1.String())
	assert.NoError(t, err)
	assert.True(t, ok)

	info, err = db.Get(h1.String())
	assert.NoError(t, err)
	assert.Equal(t, h1.String(), info.Hash)

	// permanently delete known
	ok, err = db.Delete(h1.String())
	assert.NoError(t, err)
	assert.True(t, ok)

	// cannot undelete
	ok, err = db.SoftUndelete(h1.String())
	assert.Error(t, err)
	assert.False(t, ok)

	info, err = db.Get(h1.String())
	assert.Error(t, err)
	assert.Nil(t, info)
}
