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
	"testing"
	"time"

	pkgAddress "github.com/bitmaelum/bitmaelum-suite/pkg/address"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	"github.com/bitmaelum/key-resolver-go/internal/address"
	"github.com/bitmaelum/key-resolver-go/internal/http"
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
	addr, _ := pkgAddress.NewAddress("example!")
	pow := proofofwork.New(22, addr.Hash().String(), 1540921)

	sr := address.NewSqliteResolver(":memory:")
	address.SetDefaultRepository(sr)
	sr.TimeNow = time.Date(2010, 04, 07, 12, 34, 56, 0, time.UTC)

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

	// Insert with too small proof of work
	pow2 = proofofwork.New(5, addr.Hash().String(), 16)
	res = insertAddressRecord(*addr, "../../testdata/key-4.json", fakeRoutingId.String(), "", pow2)
	assert.NotNil(t, res)
	assert.Equal(t, 401, res.StatusCode)
	assert.Contains(t, res.Body, "incorrect proof-of-work")

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

func TestAddressUpdate(t *testing.T) {
	addr1, _ := pkgAddress.NewAddress("foo!")
	pow1 := proofofwork.New(22, addr1.Hash().String(), 1310761)

	addr2, _ := pkgAddress.NewAddress("bar!")
	pow2 := proofofwork.New(22, addr2.Hash().String(), 1019732)


	sr := address.NewSqliteResolver(":memory:")
	address.SetDefaultRepository(sr)
	sr.TimeNow = time.Date(2010, 04, 07, 12, 34, 56, 0, time.UTC)

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

	// Update record with correct auth
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER 2UxSWVAUJ/iIr59x76B9bF/CeQXDi4dTY4D73P8iJwE/CRaIpRyg1RHMbfLVM6fz3sfOammn8wzhooxfv6BVAg==")
	sr.TimeNow = time.Date(2010, 12, 13, 12, 34, 56, 1241511, time.UTC)
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
	addr1, _ := pkgAddress.NewAddress("foo!")
	pow1 := proofofwork.New(22, addr1.Hash().String(), 1310761)

	addr2, _ := pkgAddress.NewAddress("bar!")
	pow2 := proofofwork.New(22, addr2.Hash().String(), 1019732)


	sr := address.NewSqliteResolver(":memory:")
	address.SetDefaultRepository(sr)
	sr.TimeNow = time.Date(2010, 04, 07, 12, 34, 56, 0, time.UTC)

	// Insert some records
	res := insertAddressRecord(*addr1, "../../testdata/key-3.json", fakeRoutingId.String(), "", pow1)
	assert.NotNil(t, res)
	res = insertAddressRecord(*addr2, "../../testdata/key-4.json", fakeRoutingId.String(), "", pow2)
	assert.NotNil(t, res)

	// Delete hash without auth
	req := http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "Bearer sdfafsadf")
	res = DeleteAddressHash("efd5631354d823cd64aa8df8149cc317ae30d319295b491e86e9a5ffdab8fd7e", req)
	assert.Equal(t, 401, res.StatusCode)

	req = http.NewRequest("GET", "/", "")
	res = GetAddressHash("efd5631354d823cd64aa8df8149cc317ae30d319295b491e86e9a5ffdab8fd7e", req)
	assert.Equal(t, 200, res.StatusCode)

	// Delete hash with wrong auth
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER okqF4rW/bFoNvmxk29NLb3lbTHCpir8A86i4IiK0j6211+WMOFCr91RodeBLSCXx167VOhC/++")
	res = DeleteAddressHash("efd5631354d823cd64aa8df8149cc317ae30d319295b491e86e9a5ffdab8fd7e", req)
	assert.Equal(t, 401, res.StatusCode)

	// Delete wrong hash with wrong auth
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER okqF4rW/bFoNvmxk29NLb3lbTHCpir8A86i4IiK0j6211+WMOFCr91RodeBLSCXx167VOhC/++wes1RLx7Q1O26cmcvpsAV/7I0e+ISDSzHHW82zuvLw0IaqZ7xngrkz4QdG00VGi3mS6bNSjQqU4Yxrqoiwk/o/jVD0/MHLxYbJHn+taL2sEeSMBvfkc5zHoqsNAgZQ7anvAsYASF30NR3pGvp/66P801sYxJYrIv4b48U2Z3pQZHozDY2e4YUA+14ZWZIYqQ+K8yCa78KTSTy5mDznP2Hpvnsy6sT8R93u2aLk++vLCmRby3REGfYRaWDxSGxgXjCgVqiLdFRLhg==")
	res = DeleteAddressHash("00000000000000000000000000000317ae30d319295b491e86e9a5ffdab8fd7e", req)
	assert.Equal(t, 500, res.StatusCode)

	// Delete hash with auth
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER 2UxSWVAUJ/iIr59x76B9bF/CeQXDi4dTY4D73P8iJwE/CRaIpRyg1RHMbfLVM6fz3sfOammn8wzhooxfv6BVAg==")
	res = DeleteAddressHash("efd5631354d823cd64aa8df8149cc317ae30d319295b491e86e9a5ffdab8fd7e", req)
	assert.Equal(t, 200, res.StatusCode)

	// @TODO: test remove by organisation

	req = http.NewRequest("GET", "/", "")
	res = GetAddressHash(addr1.Hash(), req)
	assert.Equal(t, 404, res.StatusCode)
	res = GetAddressHash(addr2.Hash(), req)
	assert.Equal(t, 200, res.StatusCode)
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
