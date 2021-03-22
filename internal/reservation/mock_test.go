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

package reservation

import (
	"testing"

	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/stretchr/testify/assert"
)

func TestMockRepository(t *testing.T) {
	r := NewMockRepository()

	h := hash.New("foobar")
	r.AddEntry(h, []string{"foobar.com", "foobar.nl"})

	ok, err := r.IsReserved(h)
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, err = r.IsReserved(hash.New("not-reserved"))
	assert.NoError(t, err)
	assert.False(t, ok)

	d, err := r.GetDomains(hash.New("not-reserved"))
	assert.NoError(t, err)
	assert.Len(t, d, 0)

	d, err = r.GetDomains(hash.New("foobar"))
	assert.NoError(t, err)
	assert.Len(t, d, 2)

	_, pk, _ := bmcrypto.GenerateKeyPair(bmcrypto.KeyTypeED25519)

	ok, err = r.IsValidated(h, pk)
	assert.NoError(t, err)
	assert.False(t, ok)

	r.AddDNS("foobar.nl", pk.Fingerprint())

	ok, err = r.IsValidated(h, pk)
	assert.NoError(t, err)
	assert.True(t, ok)
}
