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

package handler

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	pkgAddress "github.com/bitmaelum/bitmaelum-suite/pkg/address"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	"github.com/bitmaelum/key-resolver-go/internal/address"
	"github.com/bitmaelum/key-resolver-go/internal/http"
	"github.com/bitmaelum/key-resolver-go/internal/organisation"
	"github.com/bitmaelum/key-resolver-go/internal/reservation"
	"github.com/bitmaelum/key-resolver-go/internal/routing"
	testing2 "github.com/bitmaelum/key-resolver-go/internal/testing"
	"github.com/stretchr/testify/assert"
)

var (
	fakeRoutingId = hash.New("routeid")
)

type addressInfoType = struct {
	Hash         string    `json:"hash"`
	PublicKey    string    `json:"public_key"`
	Routing      string    `json:"routing_id"`
	Proof        string    `json:"proof"`
	SerialNumber uint64    `json:"serial_number"`
	Deleted      bool      `json:"deleted"`
	DeletedAt    time.Time `json:"deleted_at"`
}

func TestAddress(t *testing.T) {
	setupRepo()

	addr, _ := pkgAddress.NewAddress("example!")
	pow := proofofwork.New(22, addr.Hash().String(), 1540921)

	// Test fetching unknown hash
	req := http.NewRequest("GET", "/", "", nil)
	res := GetAddressHash("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", req)
	assert.Equal(t, 404, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"hash not found\",\"status\": \"error\"}", res.Body)

	// Insert illegal body
	req = http.NewRequest("GET", "/", "illegal body that should error", nil)
	res = PostAddressHash("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", req)
	assert.Equal(t, 400, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"invalid data\",\"status\": \"error\"}", res.Body)

	// Insert with illegal proof-of-work
	pow2 := proofofwork.New(22, "somethingelse", 4231918)
	res = insertAddressRecord(*addr, "../../testdata/key-3.json", fakeRoutingId.String(), pow2, "")
	assert.NotNil(t, res)
	assert.Equal(t, 401, res.StatusCode)
	assert.Contains(t, res.Body, "incorrect proof-of-work")

	// Insert with incorrect proof-of-work
	pow2 = proofofwork.New(22, "somethingelse", 1111111)
	res = insertAddressRecord(*addr, "../../testdata/key-3.json", fakeRoutingId.String(), pow2, "")
	assert.NotNil(t, res)
	assert.Equal(t, 401, res.StatusCode)
	assert.Contains(t, res.Body, "incorrect proof-of-work")

	// Insert with too small proof of work
	pow2 = proofofwork.New(3, addr.Hash().String(), 16)
	res = insertAddressRecord(*addr, "../../testdata/key-4.json", fakeRoutingId.String(), pow2, "")
	assert.NotNil(t, res)
	assert.Equal(t, 401, res.StatusCode)
	assert.Contains(t, res.Body, "proof-of-work too weak (need 5 bits)")

	// Insert new hash
	res = insertAddressRecord(*addr, "../../testdata/key-4.json", fakeRoutingId.String(), pow, "")
	assert.NotNil(t, res)
	assert.Equal(t, 201, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"address has been created\",\"status\": \"ok\"}", res.Body)

	// Test fetching known hash
	req = http.NewRequest("GET", "/", "", nil)
	res = GetAddressHash(addr.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	info := getAddressRecord(res)
	assert.Equal(t, "2244643da7475120bf84d744435d15ea297c36ca165ea0baaa69ec818d0e952f", info.Hash)
	assert.Equal(t, "ed25519 MCowBQYDK2VwAyEA0zlS1exf5ZbxneUfQHbiiwPkDOJoXlkAQolRRGD1K4g=", info.PubKey)
	assert.Equal(t, "f5c62bf28bb19b66d67d869acb7255168fe54413442dae0c5bdd626b8eac927e", info.RoutingID)
	assert.Equal(t, uint64(1270643696000000000), info.Serial)
}

func TestValidateVerifyHashFailed(t *testing.T) {
	setupRepo()

	_, pubKey, _ := testing2.ReadTestKey("../../testdata/key-3.json")

	addr, _ := pkgAddress.NewAddress("example!")
	pow := proofofwork.New(22, addr.Hash().String(), 1540921)

	b, _ := json.Marshal(addressUploadBody{
		UserHash:  "bar",
		OrgHash:   "foo",
		PublicKey: pubKey,
		RoutingID: "12345",
		Proof:     pow,
	})

	req := http.NewRequest("GET", "/", string(b), nil)
	res := PostAddressHash(addr.Hash(), req)
	assert.NotNil(t, res)
	assert.Equal(t, 400, res.StatusCode)
	assert.Contains(t, res.Body, "hash verification failed")
}

func TestValidateRoutingIDFailed(t *testing.T) {
	setupRepo()

	_, pubKey, _ := testing2.ReadTestKey("../../testdata/key-3.json")

	addr, _ := pkgAddress.NewAddress("example!")
	pow := proofofwork.New(22, addr.Hash().String(), 1540921)

	b, _ := json.Marshal(addressUploadBody{
		UserHash:  addr.LocalHash(),
		OrgHash:   addr.OrgHash(),
		PublicKey: pubKey,
		RoutingID: "incorrect-routing-id",
		Proof:     pow,
	})

	req := http.NewRequest("GET", "/", string(b), nil)
	res := PostAddressHash(addr.Hash(), req)
	assert.NotNil(t, res)
	assert.Equal(t, 400, res.StatusCode)
	assert.Contains(t, res.Body, "invalid routing id")
}

func TestAddressUpdate(t *testing.T) {
	setupRepo()

	addr1, _ := pkgAddress.NewAddress("foo!")
	pow1 := proofofwork.New(22, addr1.Hash().String(), 1310761)

	addr2, _ := pkgAddress.NewAddress("bar!")
	pow2 := proofofwork.New(22, addr2.Hash().String(), 1019732)

	// Insert some records
	res := insertAddressRecord(*addr1, "../../testdata/key-3.json", fakeRoutingId.String(), pow1, "")
	assert.NotNil(t, res)
	res = insertAddressRecord(*addr2, "../../testdata/key-4.json", fakeRoutingId.String(), pow2, "")
	assert.NotNil(t, res)

	// Fetch addr1 record
	req := http.NewRequest("GET", "/", "", nil)
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	current := getAddressRecord(res)

	pow := proofofwork.New(22, "foo", 1234)

	// Update record with incorrect auth
	pk, _ := bmcrypto.NewPubKey(current.PubKey)
	body := &addressUploadBody{
		UserHash:  addr1.LocalHash(),
		OrgHash:   addr1.OrgHash(),
		PublicKey: pk,
		RoutingID: hash.New("some other routing id").String(),
		Proof:     pow,
	}

	res = updateAddress(*body, req, &current)
	assert.Equal(t, 401, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"unauthenticated\",\"status\": \"error\"}", res.Body)

	// Create authentication token
	privKey, _, _ := testing2.ReadTestKey("../../testdata/key-3.json")
	sig := current.Hash + current.RoutingID + strconv.FormatUint(current.Serial, 10)
	authToken := http.GenerateAuthenticationToken([]byte(sig), *privKey)

	// Update record with correct auth
	req = http.NewRequest("GET", "/", "", nil)
	req.Headers.Set("authorization", "BEARER "+authToken)
	// req.Headers.Set("authorization", "BEARER 2UxSWVAUJ/iIr59x76B9bF/CeQXDi4dTY4D73P8iJwE/CRaIpRyg1RHMbfLVM6fz3sfOammn8wzhooxfv6BVAg==")

	setRepoTime(time.Date(2010, 12, 13, 12, 34, 56, 1241511, time.UTC))
	res = updateAddress(*body, req, &current)
	assert.Equal(t, 200, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"address has been updated\",\"status\": \"ok\"}", res.Body)

	req = http.NewRequest("GET", "/", "", nil)
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	info := getAddressRecord(res)
	assert.Equal(t, "efd5631354d823cd64aa8df8149cc317ae30d319295b491e86e9a5ffdab8fd7e", info.Hash)
	assert.Equal(t, "ed25519 MCowBQYDK2VwAyEAbRpv3o6/dvhcYwZTHM/+q8FPbz+U/qgsXDxISQv5Ab8=", info.PubKey)
	assert.Equal(t, "1a84445c73df345cf2c1ec642eb185131e0356dbddaf060abb77fde0fcd67c99", info.RoutingID)
	assert.Equal(t, uint64(1292243696001241511), info.Serial)
}

func TestAddressDeletion(t *testing.T) {
	setupRepo()

	addr1, _ := pkgAddress.NewAddress("foo!")
	pow1 := proofofwork.New(22, addr1.Hash().String(), 1310761)

	addr2, _ := pkgAddress.NewAddress("bar!")
	pow2 := proofofwork.New(22, addr2.Hash().String(), 1019732)

	// Insert some records
	res := insertAddressRecord(*addr1, "../../testdata/key-3.json", fakeRoutingId.String(), pow1, "")
	assert.NotNil(t, res)
	res = insertAddressRecord(*addr2, "../../testdata/key-4.json", fakeRoutingId.String(), pow2, "")
	assert.NotNil(t, res)

	// Delete hash without auth
	req := http.NewRequest("GET", "/", "", nil)
	req.Headers.Set("authorization", "Bearer sdfafsadf")
	res = DeleteAddressHash(addr1.Hash(), req)
	assert.Equal(t, 401, res.StatusCode)

	req = http.NewRequest("GET", "/", "", nil)
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)

	// Delete hash with wrong auth
	req = http.NewRequest("GET", "/", "", nil)
	req.Headers.Set("authorization", "BEARER okqF4rW/bFoNvmxk29NLb3lbTHCpir8A86i4IiK0j6211+WMOFCr91RodeBLSCXx167VOhC/++")
	res = DeleteAddressHash(addr1.Hash(), req)
	assert.Equal(t, 401, res.StatusCode)

	// Delete wrong hash with wrong auth
	req = http.NewRequest("GET", "/", "", nil)
	req.Headers.Set("authorization", "BEARER okqF4rW/bFoNvmxk29NLb3lbTHCpir8A86i4IiK0j6211+WMOFCr91RodeBLSCXx167VOhC/++wes1RLx7Q1O26cmcvpsAV/7I0e+ISDSzHHW82zuvLw0IaqZ7xngrkz4QdG00VGi3mS6bNSjQqU4Yxrqoiwk/o/jVD0/MHLxYbJHn+taL2sEeSMBvfkc5zHoqsNAgZQ7anvAsYASF30NR3pGvp/66P801sYxJYrIv4b48U2Z3pQZHozDY2e4YUA+14ZWZIYqQ+K8yCa78KTSTy5mDznP2Hpvnsy6sT8R93u2aLk++vLCmRby3REGfYRaWDxSGxgXjCgVqiLdFRLhg==")
	res = DeleteAddressHash("00000000000000000000000000000317ae30d319295b491e86e9a5ffdab8fd7e", req)
	assert.Equal(t, 500, res.StatusCode)

	// Fetch addr1 record
	req = http.NewRequest("GET", "/", "", nil)
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	current := getAddressRecord(res)

	// Create authentication token
	privKey, _, _ := testing2.ReadTestKey("../../testdata/key-3.json")
	sig := current.Hash + current.RoutingID + strconv.FormatUint(current.Serial, 10)
	authToken := http.GenerateAuthenticationToken([]byte(sig), *privKey)

	// Delete hash with auth
	req = http.NewRequest("GET", "/", "", nil)
	req.Headers.Set("authorization", "BEARER "+authToken)
	res = DeleteAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)

	req = http.NewRequest("GET", "/", "", nil)
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 404, res.StatusCode)
	res = GetAddressHash(addr2.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
}

func TestAddressSoftDeletion(t *testing.T) {
	setupRepo()

	addr1, _ := pkgAddress.NewAddress("foo!")
	pow1 := proofofwork.New(22, addr1.Hash().String(), 1310761)

	addr2, _ := pkgAddress.NewAddress("bar!")
	pow2 := proofofwork.New(22, addr2.Hash().String(), 1019732)

	// Insert some records
	res := insertAddressRecord(*addr1, "../../testdata/key-3.json", fakeRoutingId.String(), pow1, "")
	assert.NotNil(t, res)
	res = insertAddressRecord(*addr2, "../../testdata/key-4.json", fakeRoutingId.String(), pow2, "")
	assert.NotNil(t, res)

	// Delete hash without auth
	req := http.NewRequest("POST", "/", "", nil)
	req.Headers.Set("authorization", "Bearer sdfafsadf")
	res = SoftDeleteAddressHash(addr1.Hash(), req)
	assert.Equal(t, 401, res.StatusCode)

	req = http.NewRequest("GET", "/", "", nil)
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)

	// Delete hash with wrong auth
	req = http.NewRequest("GET", "/", "", nil)
	req.Headers.Set("authorization", "BEARER okqF4rW/bFoNvmxk29NLb3lbTHCpir8A86i4IiK0j6211+WMOFCr91RodeBLSCXx167VOhC/++")
	res = SoftDeleteAddressHash(addr1.Hash(), req)
	assert.Equal(t, 401, res.StatusCode)

	// Delete wrong hash with wrong auth
	req = http.NewRequest("GET", "/", "", nil)
	req.Headers.Set("authorization", "BEARER okqF4rW/bFoNvmxk29NLb3lbTHCpir8A86i4IiK0j6211+WMOFCr91RodeBLSCXx167VOhC/++wes1RLx7Q1O26cmcvpsAV/7I0e+ISDSzHHW82zuvLw0IaqZ7xngrkz4QdG00VGi3mS6bNSjQqU4Yxrqoiwk/o/jVD0/MHLxYbJHn+taL2sEeSMBvfkc5zHoqsNAgZQ7anvAsYASF30NR3pGvp/66P801sYxJYrIv4b48U2Z3pQZHozDY2e4YUA+14ZWZIYqQ+K8yCa78KTSTy5mDznP2Hpvnsy6sT8R93u2aLk++vLCmRby3REGfYRaWDxSGxgXjCgVqiLdFRLhg==")
	res = SoftDeleteAddressHash("00000000000000000000000000000317ae30d319295b491e86e9a5ffdab8fd7e", req)
	assert.Equal(t, 500, res.StatusCode)

	// Fetch addr1 record
	req = http.NewRequest("GET", "/", "", nil)
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	current := getAddressRecord(res)

	// Create authentication token
	privKey, _, _ := testing2.ReadTestKey("../../testdata/key-3.json")
	sig := current.Hash + current.RoutingID + strconv.FormatUint(current.Serial, 10)
	authToken := http.GenerateAuthenticationToken([]byte(sig), *privKey)

	// Soft delete hash with auth
	req = http.NewRequest("GET", "/", "", nil)
	req.Headers.Set("authorization", "BEARER "+authToken)
	res = SoftDeleteAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"address has been soft-deleted\",\"status\": \"ok\"}", res.Body)

	req = http.NewRequest("GET", "/", "", nil)
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 404, res.StatusCode)
	res = GetAddressHash(addr2.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)

	// Soft undelete hash with auth
	req = http.NewRequest("GET", "/", "", nil)
	req.Headers.Set("authorization", "BEARER "+authToken)
	res = SoftUndeleteAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"address has been undeleted\",\"status\": \"ok\"}", res.Body)

	req = http.NewRequest("GET", "/", "", nil)
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	res = GetAddressHash(addr2.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
}

func TestHistory(t *testing.T) {
	setupRepo()

	addr, _ := pkgAddress.NewAddress("example!")
	addr2, _ := pkgAddress.NewAddress("someoneelse!")
	pow := proofofwork.New(22, addr.Hash().String(), 1540921)

	_, pub, _ := testing2.ReadTestKey("../../testdata/key-4.json")
	_, pub2, _ := testing2.ReadTestKey("../../testdata/key-3.json")

	// Insert new hash
	res := insertAddressRecord(*addr, "../../testdata/key-4.json", fakeRoutingId.String(), pow, "")
	assert.NotNil(t, res)
	assert.Equal(t, 201, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"address has been created\",\"status\": \"ok\"}", res.Body)

	// Test history of key
	req := http.NewRequest("GET", "/address/"+addr.Hash().String()+"/check/"+pub.Fingerprint(), "", map[string]string{
		"fingerprint": pub.Fingerprint(),
	})
	res = GetKeyStatus(addr.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"normal\",\"status\": \"ok\"}", res.Body)

	// Check history of non-existing key
	req = http.NewRequest("GET", "/address/"+addr.Hash().String()+"/check/"+pub2.Fingerprint(), "", map[string]string{
		"fingerprint": pub2.Fingerprint(),
	})
	res = GetKeyStatus(addr.Hash(), req)
	assert.Equal(t, 404, res.StatusCode)

	// Check history of existing key on different account
	req = http.NewRequest("GET", "/address/"+addr2.Hash().String()+"/check/"+pub.Fingerprint(), "", map[string]string{
		"fingerprint": pub.Fingerprint(),
	})
	res = GetKeyStatus(addr2.Hash(), req)
	assert.Equal(t, 404, res.StatusCode)

	// Set key to unknown status
	req = http.NewRequest("GET", "/address/"+addr.Hash().String()+"/check/"+pub.Fingerprint(), "{\"status\":\"unknown\"}", map[string]string{
		"fingerprint": pub.Fingerprint(),
	})
	res = SetKeyStatus(addr.Hash(), req)
	assert.Equal(t, 400, res.StatusCode)

	// Set key to compromised
	req = http.NewRequest("GET", "/address/"+addr.Hash().String()+"/check/"+pub.Fingerprint(), "{\"status\":\"compromised\"}", map[string]string{
		"fingerprint": pub.Fingerprint(),
	})
	res = SetKeyStatus(addr.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)

	// Check history of key again
	req = http.NewRequest("GET", "/address/"+addr.Hash().String()+"/check/"+pub.Fingerprint(), "", map[string]string{
		"fingerprint": pub.Fingerprint(),
	})
	res = GetKeyStatus(addr.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"compromised\",\"status\": \"ok\"}", res.Body)

	// Set key to normal
	req = http.NewRequest("GET", "/address/"+addr.Hash().String()+"/check/"+pub.Fingerprint(), "{\"status\":\"normal\"}", map[string]string{
		"fingerprint": pub.Fingerprint(),
	})
	res = SetKeyStatus(addr.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
}

func setupRepo() {
	// NO reservation checks
	reservation.ReservationService = reservation.NewMockRepository()

	sr := address.NewSqliteResolver(":memory:")
	address.SetDefaultRepository(sr)

	sr2 := organisation.NewSqliteResolver(":memory:")
	organisation.SetDefaultRepository(sr2)

	sr3 := routing.NewSqliteResolver(":memory:")
	routing.SetDefaultRepository(sr3)

	setRepoTime(time.Date(2010, 04, 07, 12, 34, 56, 0, time.UTC))

	// Decrease number of bits for testing purposes
	MinimumProofBitsAddress = 5
	MinimumProofBitsOrganisation = 5
}

func setRepoTime(t time.Time) {
	r1 := organisation.GetResolveRepository()
	r1.(*organisation.SqliteDbResolver).TimeNow = t

	r2 := routing.GetResolveRepository()
	r2.(*routing.SqliteDbResolver).TimeNow = t

	r3 := address.GetResolveRepository()
	r3.(*address.SqliteDbResolver).TimeNow = t

	address.TimeNow = func() time.Time {
		return t
	}
}

func updateAddressRecord(addr pkgAddress.Address, keyPath, routingId string, redir string) *http.Response {
	_, pubKey, _ := testing2.ReadTestKey(keyPath)

	req := http.NewRequest("GET", "/", "", nil)
	res := GetAddressHash(addr.Hash(), req)
	info := getAddressRecord(res)

	repo := address.GetResolveRepository()
	_, _ = repo.Update(&info, routingId, pubKey, redir)

	return nil
}

func insertAddressRecord(addr pkgAddress.Address, keyPath, routingId string, pow *proofofwork.ProofOfWork, redir string) *http.Response {
	_, pubKey, err := testing2.ReadTestKey(keyPath)
	if err != nil {
		return nil
	}

	b, err := json.Marshal(addressUploadBody{
		UserHash:  addr.LocalHash(),
		OrgHash:   addr.OrgHash(),
		RedirHash: redir,
		PublicKey: pubKey,
		RoutingID: routingId,
		Proof:     pow,
	})
	if err != nil {
		return nil
	}
	req := http.NewRequest("GET", "/", string(b), nil)

	return PostAddressHash(addr.Hash(), req)
}

func getAddressRecord(res *http.Response) address.ResolveInfoType {
	tmp := &addressInfoType{}
	_ = json.Unmarshal([]byte(res.Body), tmp)

	return address.ResolveInfoType{
		Hash:      tmp.Hash,
		RoutingID: tmp.Routing,
		PubKey:    tmp.PublicKey,
		Proof:     tmp.Proof,
		Serial:    tmp.SerialNumber,
		Deleted:   tmp.Deleted,
		DeletedAt: tmp.DeletedAt,
	}
}

func TestRedirections(t *testing.T) {
	setupRepo()

	addr1, _ := pkgAddress.NewAddress("aaa!")
	pow1 := proofofwork.New(MinimumProofBitsAddress, addr1.Hash().String(), 0)
	pow1.WorkMulticore()
	addr2, _ := pkgAddress.NewAddress("bbb!")
	pow2 := proofofwork.New(MinimumProofBitsAddress, addr2.Hash().String(), 0)
	pow2.WorkMulticore()
	addr3, _ := pkgAddress.NewAddress("ccc!")
	pow3 := proofofwork.New(MinimumProofBitsAddress, addr3.Hash().String(), 0)
	pow3.WorkMulticore()
	// addr4, _ := pkgAddress.NewAddress("ddd!")
	// pow4 := proofofwork.New(22, addr4.Hash().String(), 1540921)

	// Insert some records
	insertAddressRecord(*addr2, "../../testdata/key-2.json", fakeRoutingId.String(), pow2, "")
	insertAddressRecord(*addr1, "../../testdata/key-1.json", fakeRoutingId.String(), pow1, addr2.Hash().String())
	insertAddressRecord(*addr3, "../../testdata/key-3.json", fakeRoutingId.String(), pow3, addr1.Hash().String())

	req := http.NewRequest("GET", "/", "", nil)
	res := GetAddressHash(addr3.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	info := getAddressRecord(res)
	assert.Equal(t, "c83ce9b6948f49423ef5bcea1db597b89811dbc181c52bc573c0f87fba59e3a5", info.Hash)
	assert.Equal(t, "rsa MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwj+dRyW55NXuBPF9/YOBP8VXL3QNYesGByEuKiZMOJkSnMg92FfKAF7EflGPp3GREF27DGCJurYDqBHFuBxFkJ3gUVD6AeQTlVGgvJ7MOhyhpMuIICqSw2WJZ+P3PM8d8fqHammwg0plsLFyZvrhFSbN6T/HYTaZfe0jO4iIxqR5SwhTY0JOKULmDVjVu5BgX9jzNA+nkr3OQ3HUuxgwmOMwCJkz9QEhv8/fROZNHR7xjDJ9iCUSswqPIlphJEH2hdV/UVVxX7bi36yze1IliR9VpOyS/VmlEE9M3k1mQ6r/vInGHdWBrmA8ri5J+EthawWA3dtwEgu9+iVCqrVVkwIDAQAB", info.PubKey)
}

// test redirection
func TestDepth(t *testing.T) {
	setupRepo()

	addr1, _ := pkgAddress.NewAddress("aaa!")
	pow1 := proofofwork.New(MinimumProofBitsAddress, addr1.Hash().String(), 0)
	pow1.WorkMulticore()
	addr2, _ := pkgAddress.NewAddress("bbb!")
	pow2 := proofofwork.New(MinimumProofBitsAddress, addr2.Hash().String(), 0)
	pow2.WorkMulticore()
	addr3, _ := pkgAddress.NewAddress("ccc!")
	pow3 := proofofwork.New(MinimumProofBitsAddress, addr3.Hash().String(), 0)
	pow3.WorkMulticore()
	addr4, _ := pkgAddress.NewAddress("ddd!")
	pow4 := proofofwork.New(MinimumProofBitsAddress, addr4.Hash().String(), 0)
	pow4.WorkMulticore()
	addr5, _ := pkgAddress.NewAddress("eee!")
	pow5 := proofofwork.New(MinimumProofBitsAddress, addr5.Hash().String(), 0)
	pow5.WorkMulticore()

	// Insert some records
	insertAddressRecord(*addr1, "../../testdata/key-1.json", fakeRoutingId.String(), pow1, "")
	insertAddressRecord(*addr2, "../../testdata/key-2.json", fakeRoutingId.String(), pow2, addr1.Hash().String())
	insertAddressRecord(*addr3, "../../testdata/key-3.json", fakeRoutingId.String(), pow3, addr2.Hash().String())
	insertAddressRecord(*addr4, "../../testdata/key-4.json", fakeRoutingId.String(), pow4, addr3.Hash().String())

	MaxRedirectDepth = 2

	req := http.NewRequest("GET", "/", "", nil)
	res := GetAddressHash(addr4.Hash(), req)
	assert.Equal(t, 400, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"maximum redirection reached\",\"status\": \"error\"}", res.Body)

	res = GetAddressHash(addr3.Hash(), req)
	assert.Equal(t, 400, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"maximum redirection reached\",\"status\": \"error\"}", res.Body)

	res = GetAddressHash(addr2.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)

	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)

	// Add new entry should not work with redir
	resp := insertAddressRecord(*addr5, "../../testdata/key-5.json", fakeRoutingId.String(), pow5, addr4.Hash().String())
	assert.Equal(t, 400, resp.StatusCode)
	assert.JSONEq(t, "{\"message\": \"maximum redirection reached\",\"status\": \"error\"}", resp.Body)

	resp = insertAddressRecord(*addr5, "../../testdata/key-5.json", fakeRoutingId.String(), pow5, "")
	assert.Equal(t, 201, resp.StatusCode)
	assert.JSONEq(t, "{\"message\": \"address has been created\",\"status\": \"ok\"}", resp.Body)
}

// test depth
func TestCyclic(t *testing.T) {
	setupRepo()

	addr1, _ := pkgAddress.NewAddress("aaa!")
	pow1 := proofofwork.New(MinimumProofBitsAddress, addr1.Hash().String(), 0)
	pow1.WorkMulticore()
	addr2, _ := pkgAddress.NewAddress("bbb!")
	pow2 := proofofwork.New(MinimumProofBitsAddress, addr2.Hash().String(), 0)
	pow2.WorkMulticore()
	addr3, _ := pkgAddress.NewAddress("ccc!")
	pow3 := proofofwork.New(MinimumProofBitsAddress, addr3.Hash().String(), 0)
	pow3.WorkMulticore()
	addr4, _ := pkgAddress.NewAddress("ddd!")
	pow4 := proofofwork.New(MinimumProofBitsAddress, addr4.Hash().String(), 0)
	pow4.WorkMulticore()
	addr5, _ := pkgAddress.NewAddress("eee!")
	pow5 := proofofwork.New(MinimumProofBitsAddress, addr5.Hash().String(), 0)
	pow5.WorkMulticore()

	MaxRedirectDepth = 5

	// Insert some records
	insertAddressRecord(*addr4, "../../testdata/key-4.json", fakeRoutingId.String(), pow4, "")
	insertAddressRecord(*addr2, "../../testdata/key-2.json", fakeRoutingId.String(), pow2, addr4.Hash().String())
	insertAddressRecord(*addr3, "../../testdata/key-1.json", fakeRoutingId.String(), pow3, addr2.Hash().String())
	updateAddressRecord(*addr4, "../../testdata/key-4.json", fakeRoutingId.String(), addr3.Hash().String())

	req := http.NewRequest("GET", "/", "", nil)
	res := GetAddressHash(addr4.Hash(), req)
	assert.Equal(t, 400, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"cyclic dependency detected\",\"status\": \"error\"}", res.Body)

	res = GetAddressHash(addr3.Hash(), req)
	assert.Equal(t, 400, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"cyclic dependency detected\",\"status\": \"error\"}", res.Body)

	res = GetAddressHash(addr2.Hash(), req)
	assert.Equal(t, 400, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"cyclic dependency detected\",\"status\": \"error\"}", res.Body)

	// Add new entry should not work with cyclic
	resp := insertAddressRecord(*addr5, "../../testdata/key-5.json", fakeRoutingId.String(), pow5, addr4.Hash().String())
	assert.Equal(t, 400, resp.StatusCode)
	assert.JSONEq(t, "{\"message\": \"maximum redirection reached\",\"status\": \"error\"}", resp.Body)

	resp = insertAddressRecord(*addr5, "../../testdata/key-5.json", fakeRoutingId.String(), pow5, "")
	assert.Equal(t, 201, resp.StatusCode)
	assert.JSONEq(t, "{\"message\": \"address has been created\",\"status\": \"ok\"}", resp.Body)
}
