package http

import (
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
	assert.Len(t, res.Headers, 1)

	res = CreateError("", 501)
	assert.Equal(t, 501, res.StatusCode)
	assert.Equal(t, "{\n  \"error\": \"\"\n}", res.Body)
	assert.Len(t, res.Headers, 1)
}

func TestCreateOutput(t *testing.T) {
	data := map[string]string{
		"foo": "123",
		"bar": "foo",
	}

	res := CreateOutput(data, 200)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "{\n  \"bar\": \"foo\",\n  \"foo\": \"123\"\n}", res.Body)
	assert.Len(t, res.Headers, 1)
}

func TestValidateSignature(t *testing.T) {
	var req Request
	var hashData = "foobar data test"

	req = Request{}
	req.Headers = make(map[string]string)
	req.Headers["Authorization"] = "Bearer " + Signature
	assert.True(t, req.ValidateSignature(PubKeyData, hashData))

	req = Request{}
	req.Headers = make(map[string]string)
	req.Headers["Authorization"] = "Bearer " + Signature
	assert.False(t, req.ValidateSignature("false data", hashData))

	req = Request{}
	req.Headers = make(map[string]string)
	req.Headers["Authorization"] = "Bearer " + Signature
	assert.False(t, req.ValidateSignature(PubKeyData, hashData+"falsefalse"))

	req = Request{}
	req.Headers = make(map[string]string)
	req.Headers["Authorization"] = "ADSAFAFAF"
	assert.False(t, req.ValidateSignature(PubKeyData, hashData))

	req = Request{}
	req.Headers = make(map[string]string)
	req.Headers["Authorization"] = "Bearer *&^(&^%(^&#@%$%)@$%@!$^@$^)@!"
	assert.False(t, req.ValidateSignature(PubKeyData, hashData))

	req = Request{}
	req.Headers = make(map[string]string)
	req.Headers["Authorization"] = ""
	assert.False(t, req.ValidateSignature(PubKeyData, hashData))
}
