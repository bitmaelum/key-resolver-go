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
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	"github.com/bitmaelum/bitmaelum-suite/pkg/address"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
)

var timeNow = time.Now

func VerifyInviteToken(token string, addrHash *address.HashAddress, routingID string, key bmcrypto.PubKey) bool {
	tokenData, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return false
	}

	parts := strings.SplitN(string(tokenData), ":", 4)
	if len(parts) != 4 {
		return false
	}

	// Check signature first
	hash := sha256.Sum256([]byte(parts[0] + parts[1] + parts[2]))
	ok, err := bmcrypto.Verify(key, hash[:], []byte(parts[3]))
	if err != nil || !ok {
		return false
	}

	// Check address
	if addrHash.String() != parts[0] {
		return false
	}

	// Check routing
	if routingID != parts[1] {
		return false
	}

	// Check expiry
	ts, err := strconv.Atoi(parts[2])
	if err != nil {
		return false
	}
	expiry := time.Unix(int64(ts), 0)
	return !timeNow().After(expiry)
}
