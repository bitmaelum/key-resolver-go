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
	"testing"

	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/stretchr/testify/assert"
)

func TestSqliteDbResolver(t *testing.T) {
	db := NewSqliteResolver(":memory:")
	runRepositoryCreateUpdateTest(t, db)

	db = NewSqliteResolver(":memory:")
	runRepositoryDeletionTests(t, db)
}

func runRepositoryCreateUpdateTest(t *testing.T, db Repository) {
	h1 := hash.Hash("address1!")
	h2 := hash.Hash("address2!")

	// Create key
	ok, err := db.Create(h1.String(), "12345678", "key", "proof")
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
	assert.Equal(t, "key", info.PubKey)
	assert.Equal(t, "proof", info.Proof)

	// Update info
	ok, err = db.Update(info, "11112222", "pubkey2")
	assert.NoError(t, err)
	assert.True(t, ok)

	// Fetch info
	info, err = db.Get(h1.String())
	assert.NoError(t, err)
	assert.Equal(t, "11112222", info.RoutingID)
	assert.Equal(t, h1.String(), info.Hash)
	assert.Equal(t, "pubkey2", info.PubKey)
	assert.Equal(t, "proof", info.Proof)

	// Try and update with incorrect serial number
	info.Serial = 1234
	ok, err = db.Update(info, "88881111", "pubkey_4")
	assert.False(t, ok)
	assert.Error(t, err)

	// Read back unmodified info
	info, err = db.Get(h1.String())
	assert.NoError(t, err)
	assert.Equal(t, "11112222", info.RoutingID)
	assert.Equal(t, h1.String(), info.Hash)
	assert.Equal(t, "pubkey2", info.PubKey)
	assert.Equal(t, "proof", info.Proof)
}

func runRepositoryDeletionTests(t *testing.T, db Repository) {
	h1 := hash.Hash("address1!")
	h2 := hash.Hash("address2!")

	// Create key
	ok, err := db.Create(h1.String(), "12345678", "key", "proof")
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
