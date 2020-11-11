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

	"github.com/bitmaelum/bitmaelum-suite/pkg/address"
	testing2 "github.com/bitmaelum/key-resolver-go/internal/testing"
	"github.com/stretchr/testify/assert"
)

func TestToken(t *testing.T) {
	_, pubKey, err := testing2.ReadTestKey("../../testdata/key-1.json")
	assert.NoError(t, err)
	_, pubKey2, err := testing2.ReadTestKey("../../testdata/key-2.json")
	assert.NoError(t, err)

	timeNow = func() time.Time {
		return time.Date(2010, 05, 10, 12, 34, 56, 0, time.UTC)
	}

	addr, err := address.NewHash("jay@acme!")
	assert.NoError(t, err)
	addr2, err := address.NewHash("jane@acme!")
	assert.NoError(t, err)

	token := "MTc0NTM3NDAyODY4YTJhZTM1MjczY2M5YTM4ODFkNWU0MzU5YTljZTMwYWQyNDFhOGU0MDM3ZGQzNDYzN2RhOToxMjM0NTY3ODoxMjc0MDk5Njk2OnMhfr5xNKXid1JJR+BewdMH09GrmG/q0oM2l3nYUZkXOXdYhwpzxfL4jkalc3MuVWjbGozSyRhpGOyoLyz3wWfMm+VOxxIDAwYEVL9zlXA0tLAWEf1W+QXgZsKDCvzs2quiekOx6i0PPBBvXKqdlarPoBil8IsgXRedpQlkfMimeB0GQpjV19T1TZv5frKhqkSM1ZrNHw+dU2SiHwYTyGKpglxZTnfh5Aj33Qh+5AUZYSxbLMXqKENjWcvYd+4FflRLF/M4ZzdVwGI9ZWTJTrnXChmh/cYY+sq2kVbmJ5tSTMTM4Tm9HapW/CUJUWuIhgQpgU++RlxktqoOvojbP4k="

	// Verify correct
	ok := VerifyInviteToken(token, addr, "12345678", *pubKey)
	assert.True(t, ok)

	// Verify incorrect token
	ok = VerifyInviteToken("32532522632$$$$@@$$@", addr, "12345678", *pubKey)
	assert.False(t, ok)

	// Verify incorrect token
	ok = VerifyInviteToken("d3Jvbmd0b2tlbjp3aXRod3JvbmdkYXRh", addr, "12345678", *pubKey)
	assert.False(t, ok)

	// Verify incorrect address
	ok = VerifyInviteToken(token, addr2, "12345678", *pubKey)
	assert.False(t, ok)

	// Verify incorrect pub key
	ok = VerifyInviteToken(token, addr, "12345678", *pubKey2)
	assert.False(t, ok)

	// Verify incorrect routing
	ok = VerifyInviteToken(token, addr, "555555555", *pubKey)
	assert.False(t, ok)

	// Verify incorrect expired time
	timeNow = func() time.Time {
		return time.Date(2010, 12, 31, 12, 34, 56, 0, time.UTC)
	}
	ok = VerifyInviteToken(token, addr, "12345678", *pubKey)
	assert.False(t, ok)
}
