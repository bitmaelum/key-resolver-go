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
	"time"

	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	testing2 "github.com/bitmaelum/key-resolver-go/internal/testing"
	"github.com/stretchr/testify/assert"
)

func TestToken(t *testing.T) {
	_, pubKey, err := testing2.ReadTestKey("../../testdata/key-3.json")
	assert.NoError(t, err)
	_, pubKey2, err := testing2.ReadTestKey("../../testdata/key-4.json")
	assert.NoError(t, err)

	TimeNow = func() time.Time {
		return time.Date(2010, 05, 10, 12, 34, 56, 0, time.UTC)
	}

	addrHash := hash.New("jay@acme!")
	assert.NoError(t, err)
	addrHash2 := hash.New("jane@acme!")
	assert.NoError(t, err)

	// token expires on 2010-9-9
	token := "MDEwZjNlY2E0YzgyN2YxNmE4M2NmZWYzNDA1OTA2NmViN2M4OGU1NjI5YTgxNjYzZmUyNThjYWNjM2VhZDJhYzoxMjM0NTY3ODoxMjg0MDIzMzQ5OlVrwfD5bU10WIrDyiIP7FotDPBYYiyOV+N7zy6GQonmN25pLDoXhG6v3UzzY/KZpM4UXIJnXYSEvUIZaCKj6QQ="

	// Verify correct
	ok := VerifyInviteToken(token, addrHash, "12345678", *pubKey)
	assert.True(t, ok)

	// Verify incorrect token
	ok = VerifyInviteToken("32532522632$$$$@@$$@", addrHash, "12345678", *pubKey)
	assert.False(t, ok)

	// Verify incorrect token
	ok = VerifyInviteToken("d3Jvbmd0b2tlbjp3aXRod3JvbmdkYXRh", addrHash, "12345678", *pubKey)
	assert.False(t, ok)

	// Verify incorrect address
	ok = VerifyInviteToken(token, addrHash2, "12345678", *pubKey)
	assert.False(t, ok)

	// Verify incorrect pub key
	ok = VerifyInviteToken(token, addrHash, "12345678", *pubKey2)
	assert.False(t, ok)

	// Verify incorrect routing
	ok = VerifyInviteToken(token, addrHash, "555555555", *pubKey)
	assert.False(t, ok)

	// Verify incorrect expired time
	TimeNow = func() time.Time {
		return time.Date(2010, 12, 31, 12, 34, 56, 0, time.UTC)
	}
	ok = VerifyInviteToken(token, addrHash, "12345678", *pubKey)
	assert.False(t, ok)
}

func TestGenerateToken(t *testing.T) {
	h1 := hash.Hash("address1")
	expires := time.Date(2010, 12, 31, 12, 34, 56, 0, time.UTC)
	priv, _, _ := testing2.ReadTestKey("../../testdata/key-1.json")

	tok := GenerateToken(h1, "12345678", expires, *priv)
	assert.Equal(t, "YWRkcmVzczE6MTIzNDU2Nzg6MTI5Mzc5ODg5NjrIdRSDpUD51Xmk+Yvfo8PI9DM/nsdJaT2I/nOikqrj/b+NdjWw7tZkEYj8/Vn63cnNdoaAO3xsFBbBClEOz+/Sfvm3JjLJ0aYVJ2IFXbRc2PxOY64ISw3xU+vYCPQLw/7goCN/2ktS5FW8qpuW8KkUepOl7hfVOHp45rJqtdtOypsvxyyPal1LxfGoVE1vg9VXPXbpQob7LS0nWUi6cKTbq2d1y3U92timd9CZofhcuX6q4J+nHuwYD1NVYz1ssDSs5wr8h/rpnCO08q3cJA24+erAsLjFjqMRCbk9wi3AogK1C3dPmrNZ8ZAAyFrMahp18qRQRirGLqdWfE5oczl6", tok)
}
