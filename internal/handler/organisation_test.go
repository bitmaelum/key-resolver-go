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

	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	"github.com/bitmaelum/key-resolver-go/internal/http"
	"github.com/bitmaelum/key-resolver-go/internal/organisation"
	testing2 "github.com/bitmaelum/key-resolver-go/internal/testing"
	"github.com/stretchr/testify/assert"
)

type organisationInfoType = struct {
	Hash         string   `json:"hash"`
	PublicKey    string   `json:"public_key"`
	Routing      string   `json:"routing"`
	Proof        string   `json:"proof"`
	Validations  []string `json:"validations"`
	SerialNumber uint64   `json:"serial_number"`
}

func TestOrganisation(t *testing.T) {
	orgHash := hash.New("acme-inc!")
	pow := proofofwork.New(22, orgHash.String(), 1783097)

	sr := organisation.NewSqliteResolver(":memory:")
	organisation.SetDefaultRepository(sr)
	sr.TimeNow = time.Date(2010, 04, 07, 12, 34, 56, 0, time.UTC)

	// Test fetching unknown hash
	req := http.NewRequest("GET", "/", "")
	res := GetOrganisationHash(orgHash, req)
	assert.Equal(t, 404, res.StatusCode)
	assert.Contains(t, res.Body, "hash not found")

	// Insert illegal body
	req = http.NewRequest("GET", "/", "illegal body that should error")
	res = PostOrganisationHash(orgHash, req)
	assert.Equal(t, 400, res.StatusCode)
	assert.Contains(t, res.Body, "invalid data")

	// Insert new hash
	res = insertOrganisationRecord(orgHash, "../../testdata/key-5.json", pow, []string{"dns: foobar.com", "dns: example.com"})
	assert.NotNil(t, res)
	assert.Equal(t, 201, res.StatusCode)
	assert.Equal(t, `"created"`, res.Body)

	// Test fetching known hash
	req = http.NewRequest("GET", "/", "")
	res = GetOrganisationHash(orgHash, req)
	assert.Equal(t, 200, res.StatusCode)
	info := getOrganisationRecord(res)
	assert.Equal(t, orgHash.String(), info.Hash)
	assert.Equal(t, "ed25519 MCowBQYDK2VwAyEAKIyMAHI66yNXeXQvGrzKu5MumKEu9geKOe+RI+4m6mk=", info.PubKey)
	assert.Len(t, info.Validations, 2)
	assert.Equal(t, "dns: foobar.com", info.Validations[0])
	assert.Equal(t, uint64(1270643696000000000), info.Serial)
}

func TestOrganisationUpdate(t *testing.T) {
	orgHash := hash.New("acme-inc!")
	pow := proofofwork.New(22, orgHash.String(), 1783097)

	sr := organisation.NewSqliteResolver(":memory:")
	organisation.SetDefaultRepository(sr)
	sr.TimeNow = time.Date(2010, 04, 07, 12, 34, 56, 0, time.UTC)

	// Insert some records
	res := insertOrganisationRecord(orgHash, "../../testdata/key-5.json", pow, []string{"dns: foobar.com", "dns: example.com"})
	//res := insertOrganisationRecord("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", "../../testdata/key-1.json", "127.0.0.1")
	assert.NotNil(t, res)
	res = insertOrganisationRecord(orgHash, "../../testdata/key-5.json", pow, []string{"dns: foobar.com", "dns: example.com"})
	//res = insertOrganisationRecord("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2", "../../testdata/key-2.json", "9.9.9.9")
	assert.NotNil(t, res)

	// Fetch record
	req := http.NewRequest("GET", "/", "")
	res = GetOrganisationHash("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", req)
	assert.Equal(t, 200, res.StatusCode)
	current := getOrganisationRecord(res)

	// Update record with incorrect auth
	pk, _ := bmcrypto.NewPubKey(current.PubKey)
	body := &organisationUploadBody{
		PublicKey: pk,
	}

	res = updateOrganisation(*body, req, &current)
	assert.Equal(t, 401, res.StatusCode)
	assert.JSONEq(t, `{ "error": "unauthenticated" }`, res.Body)

	// Update record with correct auth
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER okqF4rW/bFoNvmxk29NLb3lbTHCpir8A86i4IiK0j6211+WMOFCr91RodeBLSCXx167VOhC/++wes1RLx7Q1O26cmcvpsAV/7I0e+ISDSzHHW82zuvLw0IaqZ7xngrkz4QdG00VGi3mS6bNSjQqU4Yxrqoiwk/o/jVD0/MHLxYbJHn+taL2sEeSMBvfkc5zHoqsNAgZQ7anvAsYASF30NR3pGvp/66P801sYxJYrIv4b48U2Z3pQZHozDY2e4YUA+14ZWZIYqQ+K8yCa78KTSTy5mDznP2Hpvnsy6sT8R93u2aLk++vLCmRby3REGfYRaWDxSGxgXjCgVqiLdFRLhg==")
	sr.TimeNow = time.Date(2010, 12, 13, 12, 34, 56, 1241511, time.UTC)
	res = updateOrganisation(*body, req, &current)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, `"updated"`, res.Body)

	req = http.NewRequest("GET", "/", "")
	res = GetOrganisationHash("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", req)
	assert.Equal(t, 200, res.StatusCode)
	info := getOrganisationRecord(res)
	assert.Equal(t, "0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", info.Hash)
	assert.Equal(t, "rsa MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA04vO0K60ly4iCyfP6PLePK0uF8LYs6GGyH41diteqbPRJqzSb2kCluDF+ZOsgRKHEE5cVquWJWATPFdjQvPluUysxk/jELgDWT4lDbmTP29xIGBQHIlQIrnYaoBHU+b4LegcypMprsdw9EiV9W5R/F/bTMkJyaCD4k9cZzC+T+IEhukhvbEhzYKx62cC41K9MqJ/WBqA6wp2H7xJ/dJKPjCupNbXX9l3Qbj0r20Z43N5ef7imjftEh2kwiQNnveqh6vpnYl1B3AZC+R8ZwLihP/QaBDlh+nYuy/J3SRfM6yFYZn5YQdHKmUj08HWGVxnSuFZFeKTHw2oQ5mL+lyi6QIDAQAB", info.PubKey)

	assert.Equal(t, uint64(1292243696001241511), info.Serial)
}

func TestOrganisationDeletion(t *testing.T) {
	orgHash1 := hash.New("acme-inc")
	pow1 := proofofwork.New(22, orgHash1.String(), 1305874)

	orgHash2 := hash.New("example")
	pow2 := proofofwork.New(22, orgHash2.String(), 190734)


	sr := organisation.NewSqliteResolver(":memory:")
	organisation.SetDefaultRepository(sr)
	sr.TimeNow = time.Date(2010, 04, 07, 12, 34, 56, 0, time.UTC)

	// Insert some records
	res := insertOrganisationRecord(orgHash1, "../../testdata/key-5.json", pow1, []string{"dns: foobar.com", "dns: example.com"})
	assert.NotNil(t, res)
	res = insertOrganisationRecord(orgHash2, "../../testdata/key-6.json", pow2, []string{"dns: foobar.com", "dns: example.com"})
	assert.NotNil(t, res)

	// Delete hash without auth
	req := http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "Bearer sdfafsadf")
	res = DeleteOrganisationHash(orgHash1, req)
	assert.Equal(t, 401, res.StatusCode)

	req = http.NewRequest("GET", "/", "")
	res = GetOrganisationHash(orgHash1, req)
	assert.Equal(t, 200, res.StatusCode)

	req = http.NewRequest("GET", "/", "")
	res = GetOrganisationHash(orgHash2, req)
	assert.Equal(t, 200, res.StatusCode)


	// Delete hash with wrong auth
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER okqF4rW/bFoNvmxk29NLb3lbTHCpir8A86i4IiK0j6211+WMOFCr91RodeBLSCXx167VOhC/++")
	res = DeleteOrganisationHash(orgHash1, req)
	assert.Equal(t, 401, res.StatusCode)

	// Delete wrong hash with wrong auth
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER neftRnbcaw2mfudfSkXgBT6SJ3nEXsWzyumiIcDed8y6pBoEPkJkgqCHcwqm9TuqVycjzb3PemDYfvMmUfL9BA==")
	res = DeleteOrganisationHash("0000000000000000000000000E8B6E092FDE03C3A080E3454467E496E7B14E78", req)
	assert.Equal(t, 500, res.StatusCode)

	// Delete hash with auth
	req = http.NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "BEARER neftRnbcaw2mfudfSkXgBT6SJ3nEXsWzyumiIcDed8y6pBoEPkJkgqCHcwqm9TuqVycjzb3PemDYfvMmUfL9BA==")
	res = DeleteOrganisationHash(orgHash1, req)
	assert.Equal(t, 200, res.StatusCode)

	req = http.NewRequest("GET", "/", "")
	res = GetOrganisationHash(orgHash1, req)
	assert.Equal(t, 404, res.StatusCode)

	req = http.NewRequest("GET", "/", "")
	res = GetOrganisationHash(orgHash2, req)
	assert.Equal(t, 200, res.StatusCode)
}


func insertOrganisationRecord(orgHash hash.Hash, keyPath string, pow *proofofwork.ProofOfWork, validations []string) *http.Response {
	_, pubKey, err := testing2.ReadTestKey(keyPath)
	if err != nil {
		return nil
	}

	b, err := json.Marshal(organisationUploadBody{
		PublicKey:   pubKey,
		Proof:       pow,
		Validations: validations,
	})
	if err != nil {
		return nil
	}
	req := http.NewRequest("GET", "/", string(b))

	return PostOrganisationHash(orgHash, req)
}

func getOrganisationRecord(res *http.Response) organisation.ResolveInfoType {
	tmp := &organisationInfoType{}
	_ = json.Unmarshal([]byte(res.Body), tmp)

	return organisation.ResolveInfoType{
		Hash:        tmp.Hash,
		PubKey:      tmp.PublicKey,
		Proof:       tmp.Proof,
		Validations: tmp.Validations,
		Serial:      tmp.SerialNumber,
	}
}
