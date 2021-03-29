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

package http

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	testing2 "github.com/bitmaelum/key-resolver-go/internal/testing"
	"github.com/stretchr/testify/assert"
)

const (
	PubKeyData string = "rsa MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC57qC/BeoYcM6ijazuaCdJkbT8pvPpFEDVzf9ZQ9axswXU3mywSOaR3wflriSjmvRfUNs/BAjshgtJqgviUXx7lE5aG9mcUyvomyFFpfCR2l2Lvow0H8y7JoL6yxMSQf8gpAcaQzPB8dsfGe+DqA+5wjxXPOhC1QUcllt08yBB3wIDAQAB"
	Signature  string = "lsOsGOrY0rrs4A2CaJ3FzKLU5jx41d/Dw7gxQLUDPC4KMq6Cd3hyjZN6B8BbCDHBcZCFSd+sKvUbmM+ZCM1D6OrqYGvoRLTZJjWqbUsHRS7PkmIUWToxWxe0qo+tq5K/aYoDPJ+o6fRYTnUGILkN5+pQ8NquJqviLPCvBJVpKCo="
)

func TestCreateError(t *testing.T) {
	res := CreateError("foobar", 400)
	assert.Equal(t, 400, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"foobar\",\"status\": \"error\"}", res.Body)
	assert.Len(t, res.Headers.Headers, 1)

	res = CreateError("", 501)
	assert.Equal(t, 501, res.StatusCode)
	assert.JSONEq(t, "{\"message\": \"\",\"status\": \"error\"}", res.Body)
	assert.Len(t, res.Headers.Headers, 1)
}

func TestCreateOutput(t *testing.T) {
	data := map[string]string{
		"foo": "123",
		"bar": "foo",
	}

	res := CreateOutput(data, 200)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "{\n  \"bar\": \"foo\",\n  \"foo\": \"123\"\n}", res.Body)
	assert.Len(t, res.Headers.Headers, 1)
}

func TestValidateSignature(t *testing.T) {
	var req Request
	var hashData = "foobar data test"

	req = NewRequest("GET", "/", "", nil)
	req.Headers.Set("authorization", "Bearer "+Signature)
	assert.True(t, req.ValidateAuthenticationToken(PubKeyData, hashData))

	req = NewRequest("GET", "/", "", nil)
	req.Headers.Set("authorization", "Bearer "+Signature)
	assert.False(t, req.ValidateAuthenticationToken("false data", hashData))

	req = NewRequest("GET", "/", "", nil)
	req.Headers.Set("authorization", "Bearer "+Signature)
	assert.False(t, req.ValidateAuthenticationToken(PubKeyData, hashData+"falsefalse"))

	req = NewRequest("GET", "/", "", nil)
	req.Headers.Set("authorization", "ADSAFAFAF")
	assert.False(t, req.ValidateAuthenticationToken(PubKeyData, hashData))

	req = NewRequest("GET", "/", "", nil)
	req.Headers.Set("authorization", "Bearer *&^(&^%(^&#@%$%)@$%@!$^@$^)@!")
	assert.False(t, req.ValidateAuthenticationToken(PubKeyData, hashData))

	req = NewRequest("GET", "/", "", nil)
	req.Headers.Set("authorization", "")
	assert.False(t, req.ValidateAuthenticationToken(PubKeyData, hashData))
}

func TestMain(m *testing.M) {
	log.SetOutput(ioutil.Discard)
	os.Exit(m.Run())
}

func TestGenerateAuthenticationToken(t *testing.T) {
	priv, _, _ := testing2.ReadTestKey("../../testdata/key-1.json")

	token := GenerateAuthenticationToken([]byte("secret"), *priv)
	assert.Equal(t, "RHurMX2K6xiBrfYuyWufGegfrTArrn9Nm/MJaCswwqEpV3HTaQaeEEcQefM5RyzQoF4UIbPvHxRrbjL8u9Nns8GvpZ/ACdDN3MXOX0zVjkydX4Iit0k32PfikzX1kFvM0B7Lak7iNUoq0KMacBJ6ri+v+SCSSwvukB5dO5y4zdIOU1Dfypel62gc58+FWyIDcoVQEjb+hpAs1CVd5wNMR4iMe6sovp2JQ4FMVd0LEJLDOcfGHtv0kg+jikSt+QmR5YuKwIfjxZHA/dPkyL6bMmwizap4CfF/qBbiGADxkPQIxmPxuZ7mSPrtukIJu1DHayhbcp19ikfKvG8fBziLMg==", token)
}
