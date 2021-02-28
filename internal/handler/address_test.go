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
	"github.com/bitmaelum/key-resolver-go/internal/routing"
	testing2 "github.com/bitmaelum/key-resolver-go/internal/testing"
	"github.com/stretchr/testify/assert"
)

var (
	fakeRoutingId = hash.New("routeid")
)

type addressInfoType = struct {
	Hash         string `json:"hash"`
	PublicKey    string `json:"public_key"`
	Routing      string `json:"routing_id"`
	Proof        string `json:"proof"`
	SerialNumber uint64 `json:"serial_number"`
}

func TestAddress(t *testing.T) {
	setupRepo()

	addr, _ := pkgAddress.NewAddress("example!")
	pow := proofofwork.New(22, addr.Hash().String(), 1540921)

	// Test fetching unknown hash
	req := http.NewRequest("GET", "/", "")
	res := GetAddressHash("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", req)
	assert.Equal(t, 404, res.StatusCode)
	assert.JSONEq(t, `{ "error": "hash not found" }`, res.Body)

	// Insert illegal body
	req = http.NewRequest("GET", "/", "illegal body that should error")
	res = PostAddressHash("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", req)
	assert.Equal(t, 400, res.StatusCode)
	assert.JSONEq(t, `{ "error": "invalid data" }`, res.Body)

	// Insert with illegal proof-of-work
	pow2 := proofofwork.New(22, "somethingelse", 4231918)
	res = insertAddressRecord(*addr, "../../testdata/key-3.json", fakeRoutingId.String(), "", pow2)
	assert.NotNil(t, res)
	assert.Equal(t, 401, res.StatusCode)
	assert.Contains(t, res.Body, "incorrect proof-of-work")

	// Insert with incorrect proof-of-work
	pow2 = proofofwork.New(22, "somethingelse", 1111111)
	res = insertAddressRecord(*addr, "../../testdata/key-3.json", fakeRoutingId.String(), "", pow2)
	assert.NotNil(t, res)
	assert.Equal(t, 401, res.StatusCode)
	assert.Contains(t, res.Body, "incorrect proof-of-work")

	// Insert with too small proof of work
	pow2 = proofofwork.New(5, addr.Hash().String(), 16)
	res = insertAddressRecord(*addr, "../../testdata/key-4.json", fakeRoutingId.String(), "", pow2)
	assert.NotNil(t, res)
	assert.Equal(t, 401, res.StatusCode)
	assert.Contains(t, res.Body, "proof-of-work too weak (need 22 bits)")

	// Insert new hash
	res = insertAddressRecord(*addr, "../../testdata/key-4.json", fakeRoutingId.String(), "", pow)
	assert.NotNil(t, res)
	assert.Equal(t, 201, res.StatusCode)
	assert.Equal(t, `"created"`, res.Body)

	// Test fetching known hash
	req = http.NewRequest("GET", "/", "")
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
		OrgToken:  "",
		PublicKey: pubKey,
		RoutingID: "12345",
		Proof:     pow,
	})

	req := http.NewRequest("GET", "/", string(b))
	res := PostAddressHash(addr.Hash(), req)
	assert.NotNil(t, res)
	assert.Equal(t, 400, res.StatusCode)
	assert.Contains(t, res.Body, "invalid data")
}

func TestValidateVerifyNeedTokenForOrg(t *testing.T) {
	setupRepo()

	_, pubKey, _ := testing2.ReadTestKey("../../testdata/key-3.json")

	addr, _ := pkgAddress.NewAddress("foo@bar!")
	pow := proofofwork.New(22, addr.Hash().String(), 2021455)

	b, _ := json.Marshal(addressUploadBody{
		UserHash:  addr.LocalHash(),
		OrgHash:   addr.OrgHash(),
		OrgToken:  "",
		PublicKey: pubKey,
		RoutingID: "12345",
		Proof:     pow,
	})

	req := http.NewRequest("GET", "/", string(b))
	res := PostAddressHash(addr.Hash(), req)
	assert.NotNil(t, res)
	assert.Equal(t, 400, res.StatusCode)
	assert.Contains(t, res.Body, "invalid data")
}

func TestValidateVerifyNoTokenForNonOrg(t *testing.T) {
	setupRepo()

	_, pubKey, _ := testing2.ReadTestKey("../../testdata/key-3.json")

	addr, _ := pkgAddress.NewAddress("example!")
	pow := proofofwork.New(22, addr.Hash().String(), 1540921)

	b, _ := json.Marshal(addressUploadBody{
		UserHash:  addr.LocalHash(),
		OrgHash:   addr.OrgHash(),
		OrgToken:  "foobartoken",
		PublicKey: pubKey,
		RoutingID: "12345",
		Proof:     pow,
	})

	req := http.NewRequest("GET", "/", string(b))
	res := PostAddressHash(addr.Hash(), req)
	assert.NotNil(t, res)
	assert.Equal(t, 400, res.StatusCode)
	assert.Contains(t, res.Body, "invalid data")
}

func TestValidateRoutingIDFailed(t *testing.T) {
	setupRepo()

	_, pubKey, _ := testing2.ReadTestKey("../../testdata/key-3.json")

	addr, _ := pkgAddress.NewAddress("example!")
	pow := proofofwork.New(22, addr.Hash().String(), 1540921)

	b, _ := json.Marshal(addressUploadBody{
		UserHash:  addr.LocalHash(),
		OrgHash:   addr.OrgHash(),
		OrgToken:  "",
		PublicKey: pubKey,
		RoutingID: "incorrect-routing-id",
		Proof:     pow,
	})

	req := http.NewRequest("GET", "/", string(b))
	res := PostAddressHash(addr.Hash(), req)
	assert.NotNil(t, res)
	assert.Equal(t, 400, res.StatusCode)
	assert.Contains(t, res.Body, "invalid data")
}

func TestAddressUpdate(t *testing.T) {
	setupRepo()

	addr1, _ := pkgAddress.NewAddress("foo!")
	pow1 := proofofwork.New(22, addr1.Hash().String(), 1310761)

	addr2, _ := pkgAddress.NewAddress("bar!")
	pow2 := proofofwork.New(22, addr2.Hash().String(), 1019732)

	// Insert some records
	res := insertAddressRecord(*addr1, "../../testdata/key-3.json", fakeRoutingId.String(), "", pow1)
	assert.NotNil(t, res)
	res = insertAddressRecord(*addr2, "../../testdata/key-4.json", fakeRoutingId.String(), "", pow2)
	assert.NotNil(t, res)

	// Fetch addr1 record
	req := http.NewRequest("GET", "/", "")
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	current := getAddressRecord(res)

	pow := proofofwork.New(22, "foo", 1234)

	// Update record with incorrect auth
	pk, _ := bmcrypto.NewPubKey(current.PubKey)
	body := &addressUploadBody{
		UserHash:  addr1.LocalHash(),
		OrgHash:   addr1.OrgHash(),
		OrgToken:  "",
		PublicKey: pk,
		RoutingID: hash.New("some other routing id").String(),
		Proof:     pow,
	}

	res = updateAddress(*body, req, &current)
	assert.Equal(t, 401, res.StatusCode)
	assert.JSONEq(t, `{ "error": "unauthenticated" }`, res.Body)

	// Create authentication token
	privKey, _, _ := testing2.ReadTestKey("../../testdata/key-3.json")
	sig := current.Hash + current.RoutingID + strconv.FormatUint(current.Serial, 10)
	authToken := http.GenerateAuthenticationToken([]byte(sig), *privKey)

	// Update record with correct auth
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER "+authToken)
	// req.Headers.Set("authorization", "BEARER 2UxSWVAUJ/iIr59x76B9bF/CeQXDi4dTY4D73P8iJwE/CRaIpRyg1RHMbfLVM6fz3sfOammn8wzhooxfv6BVAg==")

	setRepoTime(time.Date(2010, 12, 13, 12, 34, 56, 1241511, time.UTC))
	res = updateAddress(*body, req, &current)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, `"updated"`, res.Body)

	req = http.NewRequest("GET", "/", "")
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
	res := insertAddressRecord(*addr1, "../../testdata/key-3.json", fakeRoutingId.String(), "", pow1)
	assert.NotNil(t, res)
	res = insertAddressRecord(*addr2, "../../testdata/key-4.json", fakeRoutingId.String(), "", pow2)
	assert.NotNil(t, res)

	// Delete hash without auth
	req := http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "Bearer sdfafsadf")
	res = DeleteAddressHash(addr1.Hash(), req)
	assert.Equal(t, 401, res.StatusCode)

	req = http.NewRequest("GET", "/", "")
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)

	// Delete hash with wrong auth
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER okqF4rW/bFoNvmxk29NLb3lbTHCpir8A86i4IiK0j6211+WMOFCr91RodeBLSCXx167VOhC/++")
	res = DeleteAddressHash(addr1.Hash(), req)
	assert.Equal(t, 401, res.StatusCode)

	// Delete wrong hash with wrong auth
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER okqF4rW/bFoNvmxk29NLb3lbTHCpir8A86i4IiK0j6211+WMOFCr91RodeBLSCXx167VOhC/++wes1RLx7Q1O26cmcvpsAV/7I0e+ISDSzHHW82zuvLw0IaqZ7xngrkz4QdG00VGi3mS6bNSjQqU4Yxrqoiwk/o/jVD0/MHLxYbJHn+taL2sEeSMBvfkc5zHoqsNAgZQ7anvAsYASF30NR3pGvp/66P801sYxJYrIv4b48U2Z3pQZHozDY2e4YUA+14ZWZIYqQ+K8yCa78KTSTy5mDznP2Hpvnsy6sT8R93u2aLk++vLCmRby3REGfYRaWDxSGxgXjCgVqiLdFRLhg==")
	res = DeleteAddressHash("00000000000000000000000000000317ae30d319295b491e86e9a5ffdab8fd7e", req)
	assert.Equal(t, 500, res.StatusCode)

	// Fetch addr1 record
	req = http.NewRequest("GET", "/", "")
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	current := getAddressRecord(res)

	// Create authentication token
	privKey, _, _ := testing2.ReadTestKey("../../testdata/key-3.json")
	sig := current.Hash + current.RoutingID + strconv.FormatUint(current.Serial, 10)
	authToken := http.GenerateAuthenticationToken([]byte(sig), *privKey)

	// Delete hash with auth
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER "+authToken)
	res = DeleteAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)

	req = http.NewRequest("GET", "/", "")
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
	res := insertAddressRecord(*addr1, "../../testdata/key-3.json", fakeRoutingId.String(), "", pow1)
	assert.NotNil(t, res)
	res = insertAddressRecord(*addr2, "../../testdata/key-4.json", fakeRoutingId.String(), "", pow2)
	assert.NotNil(t, res)

	// Delete hash without auth
	req := http.NewRequest("POST", "/", "")
	req.Headers.Set("authorization", "Bearer sdfafsadf")
	res = SoftDeleteAddressHash(addr1.Hash(), req)
	assert.Equal(t, 401, res.StatusCode)

	req = http.NewRequest("GET", "/", "")
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)

	// Delete hash with wrong auth
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER okqF4rW/bFoNvmxk29NLb3lbTHCpir8A86i4IiK0j6211+WMOFCr91RodeBLSCXx167VOhC/++")
	res = SoftDeleteAddressHash(addr1.Hash(), req)
	assert.Equal(t, 401, res.StatusCode)

	// Delete wrong hash with wrong auth
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER okqF4rW/bFoNvmxk29NLb3lbTHCpir8A86i4IiK0j6211+WMOFCr91RodeBLSCXx167VOhC/++wes1RLx7Q1O26cmcvpsAV/7I0e+ISDSzHHW82zuvLw0IaqZ7xngrkz4QdG00VGi3mS6bNSjQqU4Yxrqoiwk/o/jVD0/MHLxYbJHn+taL2sEeSMBvfkc5zHoqsNAgZQ7anvAsYASF30NR3pGvp/66P801sYxJYrIv4b48U2Z3pQZHozDY2e4YUA+14ZWZIYqQ+K8yCa78KTSTy5mDznP2Hpvnsy6sT8R93u2aLk++vLCmRby3REGfYRaWDxSGxgXjCgVqiLdFRLhg==")
	res = SoftDeleteAddressHash("00000000000000000000000000000317ae30d319295b491e86e9a5ffdab8fd7e", req)
	assert.Equal(t, 500, res.StatusCode)

	// Fetch addr1 record
	req = http.NewRequest("GET", "/", "")
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	current := getAddressRecord(res)

	// Create authentication token
	privKey, _, _ := testing2.ReadTestKey("../../testdata/key-3.json")
	sig := current.Hash + current.RoutingID + strconv.FormatUint(current.Serial, 10)
	authToken := http.GenerateAuthenticationToken([]byte(sig), *privKey)

	// Soft delete hash with auth
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER "+authToken)
	res = SoftDeleteAddressHash(addr1.Hash(), req)
	assert.Equal(t, 204, res.StatusCode)

	req = http.NewRequest("GET", "/", "")
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 404, res.StatusCode)
	res = GetAddressHash(addr2.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)

	// Soft undelete hash with auth
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER "+authToken)
	res = SoftUndeleteAddressHash(addr1.Hash(), req)
	assert.Equal(t, 204, res.StatusCode)

	req = http.NewRequest("GET", "/", "")
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	res = GetAddressHash(addr2.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
}

func TestAddOrganisationalAddresses(t *testing.T) {
	setupRepo()

	// Add organisation
	orgHash1 := hash.New("acme-inc")
	pow1 := proofofwork.New(22, orgHash1.String(), 1305874)
	_ = insertOrganisationRecord(orgHash1, "../../testdata/key-5.json", pow1, []string{})

	addr, _ := pkgAddress.NewAddress("example@acme-inc!")
	pow2 := proofofwork.New(22, addr.Hash().String(), 11741366)

	// Add address without token
	res := insertAddressRecord(*addr, "../../testdata/key-4.json", fakeRoutingId.String(), "", pow2)
	assert.NotNil(t, res)
	assert.Equal(t, 400, res.StatusCode)
	assert.Contains(t, res.Body, "need org token when creating")

	// Add address with wrong token
	res = insertAddressRecord(*addr, "../../testdata/key-4.json", fakeRoutingId.String(), "foobar", pow2)
	assert.NotNil(t, res)
	assert.Equal(t, 400, res.StatusCode)
	assert.Contains(t, res.Body, "cannot validate organisation token")

	privKey, _, _ := testing2.ReadTestKey("../../testdata/key-5.json")
	inviteToken := address.GenerateToken(addr.Hash(), fakeRoutingId.String(), time.Date(2010, 05, 05, 12, 0, 0, 0, time.UTC), *privKey)

	// Add address with incorrect routing id
	res = insertAddressRecord(*addr, "../../testdata/key-4.json", "incorrect-rout", inviteToken, pow2)
	assert.NotNil(t, res)
	assert.Equal(t, 400, res.StatusCode)
	assert.Contains(t, res.Body, "invalid data")

	// Add incorrect addr
	addr2, _ := pkgAddress.NewAddress("someone-else@acme-inc!")
	res = insertAddressRecord(*addr2, "../../testdata/key-4.json", fakeRoutingId.String(), inviteToken, pow2)
	assert.NotNil(t, res)
	assert.Equal(t, 400, res.StatusCode)
	assert.Contains(t, res.Body, "cannot validate organisation token")

	// After expiry
	setRepoTime(time.Date(2010, 06, 06, 12, 0, 0, 0, time.UTC))
	res = insertAddressRecord(*addr, "../../testdata/key-4.json", fakeRoutingId.String(), inviteToken, pow2)
	assert.NotNil(t, res)
	assert.Equal(t, 400, res.StatusCode)
	assert.Contains(t, res.Body, "cannot validate organisation token")

	// All good
	setRepoTime(time.Date(2010, 04, 07, 12, 34, 56, 0, time.UTC))
	res = insertAddressRecord(*addr, "../../testdata/key-4.json", fakeRoutingId.String(), inviteToken, pow2)
	assert.NotNil(t, res)
	assert.Equal(t, 201, res.StatusCode)
	assert.Contains(t, res.Body, "created")

	// Check if record exists
	req := http.NewRequest("GET", "/", "")
	res = GetAddressHash(addr.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	info := getAddressRecord(res)
	assert.Equal(t, "466ad1d6bc0657e22f048ebcbfbf6f7731b699fc0a895668e5447df5936e3460", info.Hash)
	assert.Equal(t, "ed25519 MCowBQYDK2VwAyEA0zlS1exf5ZbxneUfQHbiiwPkDOJoXlkAQolRRGD1K4g=", info.PubKey)
	assert.Equal(t, "f5c62bf28bb19b66d67d869acb7255168fe54413442dae0c5bdd626b8eac927e", info.RoutingID)
	assert.Equal(t, uint64(1270643696000000000), info.Serial)
}

func TestAllowUpdateToOrgAddressWithoutToken(t *testing.T) {
	setupRepo()

	// Add organisation
	orgHash1 := hash.New("acme-inc")
	pow1 := proofofwork.New(22, orgHash1.String(), 1305874)
	_ = insertOrganisationRecord(orgHash1, "../../testdata/key-5.json", pow1, []string{})

	addr, _ := pkgAddress.NewAddress("example@acme-inc!")
	pow2 := proofofwork.New(22, addr.Hash().String(), 11741366)

	privKey, _, _ := testing2.ReadTestKey("../../testdata/key-5.json")
	inviteToken := address.GenerateToken(addr.Hash(), fakeRoutingId.String(), time.Date(2010, 05, 05, 12, 0, 0, 0, time.UTC), *privKey)

	// Add address with token
	res := insertAddressRecord(*addr, "../../testdata/key-4.json", fakeRoutingId.String(), inviteToken, pow2)
	assert.NotNil(t, res)
	assert.Equal(t, 201, res.StatusCode)

	privKey, pubKey, err := testing2.ReadTestKey("../../testdata/key-4.json")
	assert.NoError(t, err)

	// Update record with without org token
	body := &addressUploadBody{
		UserHash:  addr.LocalHash(),
		OrgHash:   addr.OrgHash(),
		OrgToken:  "",
		PublicKey: pubKey,
		RoutingID: hash.New("some other routing id").String(),
		Proof:     pow2,
	}
	b, err := json.Marshal(body)
	assert.NoError(t, err)

	// Get serial
	req := http.NewRequest("GET", "/", "")
	res = GetAddressHash(addr.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	info := getAddressRecord(res)

	sig := addr.Hash().String() + info.RoutingID + strconv.FormatUint(info.Serial, 10)
	authToken := http.GenerateAuthenticationToken([]byte(sig), *privKey)

	req = http.NewRequest("POST", "/account/"+addr.Hash().String(), string(b))
	req.Headers.Set("authorization", "BEARER "+authToken)
	res = PostAddressHash(addr.Hash(), req)
	assert.Equal(t, "\"updated\"", res.Body)
	assert.Equal(t, 200, res.StatusCode)
}

func TestDeleteOrganisationalAddresses(t *testing.T) {
	setupRepo()

	// Add organisation
	orgHash1 := hash.New("acme-inc")
	pow1 := proofofwork.New(22, orgHash1.String(), 1305874)
	_ = insertOrganisationRecord(orgHash1, "../../testdata/key-5.json", pow1, []string{})

	orgHash2 := hash.New("example")
	pow2 := proofofwork.New(22, orgHash2.String(), 190734)
	_ = insertOrganisationRecord(orgHash2, "../../testdata/key-6.json", pow2, []string{})

	orgHash3 := hash.New("another")
	pow3 := proofofwork.New(22, orgHash3.String(), 21232)
	_ = insertOrganisationRecord(orgHash3, "../../testdata/key-7.json", pow3, []string{})

	addr, _ := pkgAddress.NewAddress("example@acme-inc!")
	pow4 := proofofwork.New(22, addr.Hash().String(), 11741366)

	insertRecords := func() {
		privKey, _, _ := testing2.ReadTestKey("../../testdata/key-5.json")
		inviteToken := address.GenerateToken(addr.Hash(), fakeRoutingId.String(), time.Date(2010, 05, 05, 12, 0, 0, 0, time.UTC), *privKey)

		res := insertAddressRecord(*addr, "../../testdata/key-4.json", fakeRoutingId.String(), inviteToken, pow4)
		assert.NotNil(t, res)
		assert.Equal(t, 201, res.StatusCode)
		assert.Contains(t, res.Body, "created")

		// Check if record exists
		req := http.NewRequest("GET", "/", "")
		res = GetAddressHash(addr.Hash(), req)
		assert.Equal(t, 200, res.StatusCode)
	}

	// Delete as regular user

	insertRecords()

	// Fetch addr record
	req := http.NewRequest("GET", "/", "")
	res := GetAddressHash(addr.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
	current := getAddressRecord(res)

	// Create authentication token
	privKey, _, _ := testing2.ReadTestKey("../../testdata/key-4.json")
	sig := current.Hash + current.RoutingID + strconv.FormatUint(current.Serial, 10)
	authToken := http.GenerateAuthenticationToken([]byte(sig), *privKey)

	// Delete as "regular" user
	req = http.NewRequest("GET", "/", "")
	// req.Headers.Set("authorization", "BEARER 2UxSWVAUJ/iIr59x76B9bF/CeQXDi4dTY4D73P8iJwE/CRaIpRyg1RHMbfLVM6fz3sfOammn8wzhooxfv6BVAg==")
	req.Headers.Set("authorization", "BEARER "+authToken)
	res = DeleteAddressHash(addr.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)

	req = http.NewRequest("GET", "/", "")
	res = GetAddressHash(addr.Hash(), req)
	assert.Equal(t, 404, res.StatusCode)

	// Delete by organisation key, but without body

	insertRecords()

	// Create authentication token
	privKey, _, _ = testing2.ReadTestKey("../../testdata/key-5.json")
	sig = addr.Hash().String() + strconv.FormatUint(current.Serial, 10)
	authToken = http.GenerateAuthenticationToken([]byte(sig), *privKey)

	// Delete as correct "organisation" user, but without body
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER "+authToken)
	res = DeleteAddressHash(addr.Hash(), req)
	assert.Equal(t, 401, res.StatusCode)

	req = http.NewRequest("GET", "/", "")
	res = GetAddressHash(addr.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)

	// Delete by organisation key, with incorrect body

	ob := &organizationRequestBody{
		UserHash:         addr.LocalHash(),
		OrganizationHash: orgHash2,
	}
	b, _ := json.Marshal(ob)

	req = http.NewRequest("GET", "/", string(b))
	req.Headers.Set("authorization", "BEARER "+authToken)
	res = DeleteAddressHash(addr.Hash(), req)
	assert.Equal(t, 401, res.StatusCode)
	assert.Contains(t, res.Body, "error validating address")

	req = http.NewRequest("GET", "/", "")
	res = GetAddressHash(addr.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)

	// Delete by organisation key, with correct body

	ob = &organizationRequestBody{
		UserHash:         addr.LocalHash(),
		OrganizationHash: addr.OrgHash(),
	}
	b, _ = json.Marshal(ob)

	req = http.NewRequest("GET", "/", string(b))
	req.Headers.Set("authorization", "BEARER "+authToken)
	res = DeleteAddressHash(addr.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)

	req = http.NewRequest("GET", "/", "")
	res = GetAddressHash(addr.Hash(), req)
	assert.Equal(t, 404, res.StatusCode)

	// Delete with auth token for org2

	// Create authentication token for ORG2
	privKey, _, _ = testing2.ReadTestKey("../../testdata/key-6.json")
	sig = addr.Hash().String() + strconv.FormatUint(current.Serial, 10)
	authToken = http.GenerateAuthenticationToken([]byte(sig), *privKey)

	// Delete as incorrect "other organisation" user
	insertRecords()

	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER "+authToken)
	res = DeleteAddressHash(addr.Hash(), req)
	assert.Equal(t, 401, res.StatusCode)

	req = http.NewRequest("GET", "/", "")
	res = GetAddressHash(addr.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
}

func setupRepo() {
	sr := address.NewSqliteResolver(":memory:")
	address.SetDefaultRepository(sr)

	sr2 := organisation.NewSqliteResolver(":memory:")
	organisation.SetDefaultRepository(sr2)

	sr3 := routing.NewSqliteResolver(":memory:")
	routing.SetDefaultRepository(sr3)

	setRepoTime(time.Date(2010, 04, 07, 12, 34, 56, 0, time.UTC))

	// Decrease number of bits for testing purposes
	MinimumProofBitsAddress = 22
	MinimumProofBitsOrganisation = 22
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

func insertAddressRecord(addr pkgAddress.Address, keyPath, routingId, orgToken string, pow *proofofwork.ProofOfWork) *http.Response {
	_, pubKey, err := testing2.ReadTestKey(keyPath)
	if err != nil {
		return nil
	}

	b, err := json.Marshal(addressUploadBody{
		UserHash:  addr.LocalHash(),
		OrgHash:   addr.OrgHash(),
		OrgToken:  orgToken,
		PublicKey: pubKey,
		RoutingID: routingId,
		Proof:     pow,
	})
	if err != nil {
		return nil
	}
	req := http.NewRequest("GET", "/", string(b))

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
	}
}
