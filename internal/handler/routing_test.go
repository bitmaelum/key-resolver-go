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

	"github.com/aws/aws-lambda-go/events"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/key-resolver-go/internal/routing"
	bmtest "github.com/bitmaelum/key-resolver-go/internal/testing"
	"github.com/stretchr/testify/assert"
)

type infoType = struct {
	Hash         string `json:"hash"`
	PublicKey    string `json:"public_key"`
	Routing      string `json:"routing"`
	SerialNumber uint64 `json:"serial_number"`
}

func TestRouting(t *testing.T) {
	sr := routing.NewSqliteResolver(":memory:")
	routing.SetDefaultRepository(sr)
	sr.TimeNow = time.Date(2010, 04, 07, 12, 34, 56, 0, time.UTC)

	// Test fetching unknown hash
	event := events.APIGatewayV2HTTPRequest{}
	res := getRoutingHash("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", event)
	assert.Equal(t, 404, res.StatusCode)
	assert.JSONEq(t, `{ "error": "hash not found" }`, res.Body)

	// Insert illegal body
	event = events.APIGatewayV2HTTPRequest{}
	event.Body = "illegal body that should error"
	res = postRoutingHash("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", event)
	assert.Equal(t, 400, res.StatusCode)
	assert.JSONEq(t, `{ "error": "invalid data" }`, res.Body)

	// Insert new hash
	res = insertRecord("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", "./testdata/key-1.json", "127.0.0.1")
	assert.NotNil(t, res)
	assert.Equal(t, 201, res.StatusCode)
	assert.Equal(t, `"created"`, res.Body)

	// Test fetching known hash
	event = events.APIGatewayV2HTTPRequest{}
	res = getRoutingHash("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", event)
	assert.Equal(t, 200, res.StatusCode)
	info := getRecord(res)
	assert.Equal(t, "0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", info.Hash)
	assert.Equal(t, "rsa MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA04vO0K60ly4iCyfP6PLePK0uF8LYs6GGyH41diteqbPRJqzSb2kCluDF+ZOsgRKHEE5cVquWJWATPFdjQvPluUysxk/jELgDWT4lDbmTP29xIGBQHIlQIrnYaoBHU+b4LegcypMprsdw9EiV9W5R/F/bTMkJyaCD4k9cZzC+T+IEhukhvbEhzYKx62cC41K9MqJ/WBqA6wp2H7xJ/dJKPjCupNbXX9l3Qbj0r20Z43N5ef7imjftEh2kwiQNnveqh6vpnYl1B3AZC+R8ZwLihP/QaBDlh+nYuy/J3SRfM6yFYZn5YQdHKmUj08HWGVxnSuFZFeKTHw2oQ5mL+lyi6QIDAQAB", info.PubKey)
	assert.Equal(t, "127.0.0.1", info.Routing)
	assert.Equal(t, uint64(1270643696000000000), info.Serial)
}

func TestUpdate(t *testing.T) {
	sr := routing.NewSqliteResolver(":memory:")
	routing.SetDefaultRepository(sr)
	sr.TimeNow = time.Date(2010, 04, 07, 12, 34, 56, 0, time.UTC)

	// Insert some records
	res := insertRecord("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", "./testdata/key-1.json", "127.0.0.1")
	assert.NotNil(t, res)
	res = insertRecord("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2", "./testdata/key-2.json", "9.9.9.9")
	assert.NotNil(t, res)

	// Fetch record
	event := events.APIGatewayV2HTTPRequest{}
	res = getRoutingHash("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", event)
	assert.Equal(t, 200, res.StatusCode)
	current := getRecord(res)

	// Update record with incorrect auth
	pk, _ := bmcrypto.NewPubKey(current.PubKey)
	body := &routingUploadBody{
		PublicKey: pk,
		Routing:   "192.168.1.5",
	}
	res = updateRouting(*body, "", &current)
	assert.Equal(t, 401, res.StatusCode)
	assert.JSONEq(t, `{ "error": "unauthenticated" }`, res.Body)

	// Update record with correct auth
	sr.TimeNow = time.Date(2010, 12, 13, 12, 34, 56, 1241511, time.UTC)
	res = updateRouting(*body, "BEARER okqF4rW/bFoNvmxk29NLb3lbTHCpir8A86i4IiK0j6211+WMOFCr91RodeBLSCXx167VOhC/++wes1RLx7Q1O26cmcvpsAV/7I0e+ISDSzHHW82zuvLw0IaqZ7xngrkz4QdG00VGi3mS6bNSjQqU4Yxrqoiwk/o/jVD0/MHLxYbJHn+taL2sEeSMBvfkc5zHoqsNAgZQ7anvAsYASF30NR3pGvp/66P801sYxJYrIv4b48U2Z3pQZHozDY2e4YUA+14ZWZIYqQ+K8yCa78KTSTy5mDznP2Hpvnsy6sT8R93u2aLk++vLCmRby3REGfYRaWDxSGxgXjCgVqiLdFRLhg==", &current)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, `"updated"`, res.Body)

	event = events.APIGatewayV2HTTPRequest{}
	res = getRoutingHash("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", event)
	assert.Equal(t, 200, res.StatusCode)
	info := getRecord(res)
	assert.Equal(t, "0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", info.Hash)
	assert.Equal(t, "rsa MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA04vO0K60ly4iCyfP6PLePK0uF8LYs6GGyH41diteqbPRJqzSb2kCluDF+ZOsgRKHEE5cVquWJWATPFdjQvPluUysxk/jELgDWT4lDbmTP29xIGBQHIlQIrnYaoBHU+b4LegcypMprsdw9EiV9W5R/F/bTMkJyaCD4k9cZzC+T+IEhukhvbEhzYKx62cC41K9MqJ/WBqA6wp2H7xJ/dJKPjCupNbXX9l3Qbj0r20Z43N5ef7imjftEh2kwiQNnveqh6vpnYl1B3AZC+R8ZwLihP/QaBDlh+nYuy/J3SRfM6yFYZn5YQdHKmUj08HWGVxnSuFZFeKTHw2oQ5mL+lyi6QIDAQAB", info.PubKey)
	assert.Equal(t, "192.168.1.5", info.Routing)
	assert.Equal(t, uint64(1292243696001241511), info.Serial)
}

func TestDeletion(t *testing.T) {
	sr := routing.NewSqliteResolver(":memory:")
	routing.SetDefaultRepository(sr)
	sr.TimeNow = time.Date(2010, 04, 07, 12, 34, 56, 0, time.UTC)

	// Insert some records
	res := insertRecord("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", "./testdata/key-1.json", "127.0.0.1")
	assert.NotNil(t, res)
	res = insertRecord("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2", "./testdata/key-2.json", "9.9.9.9")
	assert.NotNil(t, res)

	// Delete hash without auth
	event := events.APIGatewayV2HTTPRequest{}
	event.Headers = map[string]string{
		"Authorization": "Bearer sdfafsadf",
	}
	res = deleteRoutingHash("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", event)
	assert.Equal(t, 401, res.StatusCode)

	event = events.APIGatewayV2HTTPRequest{}
	res = getRoutingHash("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", event)
	assert.Equal(t, 200, res.StatusCode)

	// h := sha256.Sum256([]byte("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E781270643696000000000"))
	// buf, _ := bmcrypto.Sign(*privKey, h[:])
	// auth := base64.StdEncoding.EncodeToString(buf)
	// fmt.Println("AUTH: ", auth)

	// Delete hash with wrong auth
	event = events.APIGatewayV2HTTPRequest{}
	event.Headers = map[string]string{
		"authorization": "BEARER okqF4rW/bFoNvmxk29NLb3lbTHCpir8A86i4IiK0j6211+WMOFCr91RodeBLSCXx167VOhC/++",
	}
	res = deleteRoutingHash("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", event)
	assert.Equal(t, 401, res.StatusCode)

	// Delete wrong hash with wrong auth
	event = events.APIGatewayV2HTTPRequest{}
	event.Headers = map[string]string{
		"authorization": "BEARER okqF4rW/bFoNvmxk29NLb3lbTHCpir8A86i4IiK0j6211+WMOFCr91RodeBLSCXx167VOhC/++wes1RLx7Q1O26cmcvpsAV/7I0e+ISDSzHHW82zuvLw0IaqZ7xngrkz4QdG00VGi3mS6bNSjQqU4Yxrqoiwk/o/jVD0/MHLxYbJHn+taL2sEeSMBvfkc5zHoqsNAgZQ7anvAsYASF30NR3pGvp/66P801sYxJYrIv4b48U2Z3pQZHozDY2e4YUA+14ZWZIYqQ+K8yCa78KTSTy5mDznP2Hpvnsy6sT8R93u2aLk++vLCmRby3REGfYRaWDxSGxgXjCgVqiLdFRLhg==",
	}
	res = deleteRoutingHash("0000000000000000000000000E8B6E092FDE03C3A080E3454467E496E7B14E78", event)
	assert.Equal(t, 500, res.StatusCode)

	// Delete hash with auth
	event = events.APIGatewayV2HTTPRequest{}
	event.Headers = map[string]string{
		"authorization": "BEARER okqF4rW/bFoNvmxk29NLb3lbTHCpir8A86i4IiK0j6211+WMOFCr91RodeBLSCXx167VOhC/++wes1RLx7Q1O26cmcvpsAV/7I0e+ISDSzHHW82zuvLw0IaqZ7xngrkz4QdG00VGi3mS6bNSjQqU4Yxrqoiwk/o/jVD0/MHLxYbJHn+taL2sEeSMBvfkc5zHoqsNAgZQ7anvAsYASF30NR3pGvp/66P801sYxJYrIv4b48U2Z3pQZHozDY2e4YUA+14ZWZIYqQ+K8yCa78KTSTy5mDznP2Hpvnsy6sT8R93u2aLk++vLCmRby3REGfYRaWDxSGxgXjCgVqiLdFRLhg==",
	}
	res = deleteRoutingHash("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", event)
	assert.Equal(t, 200, res.StatusCode)

	event = events.APIGatewayV2HTTPRequest{}
	res = getRoutingHash("0CD8666848BF286D951C3D230E8B6E092FDE03C3A080E3454467E496E7B14E78", event)
	assert.Equal(t, 404, res.StatusCode)
	res = getRoutingHash("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2", event)
	assert.Equal(t, 200, res.StatusCode)
}

func insertRecord(routingHash string, keyPath string, routing string) *events.APIGatewayV2HTTPResponse {
	_, pubKey, err := bmtest.ReadTestKey(keyPath)
	if err != nil {
		return nil
	}

	b, err := json.Marshal(routingUploadBody{
		PublicKey: pubKey,
		Routing:   routing,
	})
	if err != nil {
		return nil
	}
	event := events.APIGatewayV2HTTPRequest{}
	event.Body = string(b)

	return postRoutingHash(routingHash, event)
}

func getRecord(res *events.APIGatewayV2HTTPResponse) routing.ResolveInfoType {
	tmp := &infoType{}
	_ = json.Unmarshal([]byte(res.Body), tmp)

	return routing.ResolveInfoType{
		Hash:    tmp.Hash,
		Routing: tmp.Routing,
		PubKey:  tmp.PublicKey,
		Serial:  tmp.SerialNumber,
	}
}
