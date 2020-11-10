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
