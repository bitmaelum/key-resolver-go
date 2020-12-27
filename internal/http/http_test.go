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

	"github.com/stretchr/testify/assert"
)

const (
	// PrivKeyData string = "rsa MIICXQIBAAKBgQC57qC/BeoYcM6ijazuaCdJkbT8pvPpFEDVzf9ZQ9axswXU3mywSOaR3wflriSjmvRfUNs/BAjshgtJqgviUXx7lE5aG9mcUyvomyFFpfCR2l2Lvow0H8y7JoL6yxMSQf8gpAcaQzPB8dsfGe+DqA+5wjxXPOhC1QUcllt08yBB3wIDAQABAoGBAKSWDKsrtB5wdSnFmcfsYKKqHXjs3Mp9CCt6z0eYWoswesAFKFcgISINOLNi5MICX8GkFIACtVeSDJnnsd9j3HkRD7kwxmvVVXltaIrbrEunKgdRK1ACk2Bkb7UUDImDjiZztJvCSL+WLu9Fphn8IfPzwAIPWAKKBoD1kuI6yfFBAkEA6dJpoTMKDlCEMeJWZVUnhL7K/OBphWLO7cZfaxowBeGGXuMBWiaySsdeIDV7S/PDnoHBKwIkSsSfjzWYptuq4QJBAMuRXwoqZHKPHjMTCyz3C7nwFCzgmmKM5PReZU0s4/tdFu/VGOSnVDSzC5JFcY48Cs03TBwZ2wPhv/3r4a7YRL8CQQCxedRTVro7Q0IT2whYwdnNGERazLtLU0RdlkS2tpnc3OFxBDzygIyz1b/MEswTSmMg3LwSOP3zAmtZ+AR2IiYBAkBENgnqlhniaSJtaswr3PwI6fFYuEoDC8MMPzUijxA1ghPVeUpGE+ubXQNbl/lc97GG4iiWofNJcbOrmgadV8pxAkBhsn2T9DSoDdeImRecxs3/Xej4EYQpj/3X436RrFntjT06wD6wF9s5CvPmz/ftUBJ71IVlBQUd3jOgQPRzEhNC"
	PubKeyData string = "rsa MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC57qC/BeoYcM6ijazuaCdJkbT8pvPpFEDVzf9ZQ9axswXU3mywSOaR3wflriSjmvRfUNs/BAjshgtJqgviUXx7lE5aG9mcUyvomyFFpfCR2l2Lvow0H8y7JoL6yxMSQf8gpAcaQzPB8dsfGe+DqA+5wjxXPOhC1QUcllt08yBB3wIDAQAB"
	Signature  string = "lsOsGOrY0rrs4A2CaJ3FzKLU5jx41d/Dw7gxQLUDPC4KMq6Cd3hyjZN6B8BbCDHBcZCFSd+sKvUbmM+ZCM1D6OrqYGvoRLTZJjWqbUsHRS7PkmIUWToxWxe0qo+tq5K/aYoDPJ+o6fRYTnUGILkN5+pQ8NquJqviLPCvBJVpKCo="
)

func TestCreateError(t *testing.T) {
	res := CreateError("foobar", 400)
	assert.Equal(t, 400, res.StatusCode)
	assert.Equal(t, "{\n  \"error\": \"foobar\"\n}", res.Body)
	assert.Len(t, res.Headers.Headers, 1)

	res = CreateError("", 501)
	assert.Equal(t, 501, res.StatusCode)
	assert.Equal(t, "{\n  \"error\": \"\"\n}", res.Body)
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

	req = NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "Bearer "+Signature)
	assert.True(t, req.ValidateAuthenticationToken(PubKeyData, hashData))

	req = NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "Bearer "+Signature)
	assert.False(t, req.ValidateAuthenticationToken("false data", hashData))

	req = NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "Bearer "+Signature)
	assert.False(t, req.ValidateAuthenticationToken(PubKeyData, hashData+"falsefalse"))

	req = NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "ADSAFAFAF")
	assert.False(t, req.ValidateAuthenticationToken(PubKeyData, hashData))

	req = NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "Bearer *&^(&^%(^&#@%$%)@$%@!$^@$^)@!")
	assert.False(t, req.ValidateAuthenticationToken(PubKeyData, hashData))

	req = NewRequest("GET", "/", "")
	req.Headers.Set("authorization", "")
	assert.False(t, req.ValidateAuthenticationToken(PubKeyData, hashData))
}

func TestMain(m *testing.M) {
	log.SetOutput(ioutil.Discard)
	os.Exit(m.Run())
}
