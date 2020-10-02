package main

import (
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/assert"
)

const (
	PrivKeyData string = "rsa MIICXQIBAAKBgQC57qC/BeoYcM6ijazuaCdJkbT8pvPpFEDVzf9ZQ9axswXU3mywSOaR3wflriSjmvRfUNs/BAjshgtJqgviUXx7lE5aG9mcUyvomyFFpfCR2l2Lvow0H8y7JoL6yxMSQf8gpAcaQzPB8dsfGe+DqA+5wjxXPOhC1QUcllt08yBB3wIDAQABAoGBAKSWDKsrtB5wdSnFmcfsYKKqHXjs3Mp9CCt6z0eYWoswesAFKFcgISINOLNi5MICX8GkFIACtVeSDJnnsd9j3HkRD7kwxmvVVXltaIrbrEunKgdRK1ACk2Bkb7UUDImDjiZztJvCSL+WLu9Fphn8IfPzwAIPWAKKBoD1kuI6yfFBAkEA6dJpoTMKDlCEMeJWZVUnhL7K/OBphWLO7cZfaxowBeGGXuMBWiaySsdeIDV7S/PDnoHBKwIkSsSfjzWYptuq4QJBAMuRXwoqZHKPHjMTCyz3C7nwFCzgmmKM5PReZU0s4/tdFu/VGOSnVDSzC5JFcY48Cs03TBwZ2wPhv/3r4a7YRL8CQQCxedRTVro7Q0IT2whYwdnNGERazLtLU0RdlkS2tpnc3OFxBDzygIyz1b/MEswTSmMg3LwSOP3zAmtZ+AR2IiYBAkBENgnqlhniaSJtaswr3PwI6fFYuEoDC8MMPzUijxA1ghPVeUpGE+ubXQNbl/lc97GG4iiWofNJcbOrmgadV8pxAkBhsn2T9DSoDdeImRecxs3/Xej4EYQpj/3X436RrFntjT06wD6wF9s5CvPmz/ftUBJ71IVlBQUd3jOgQPRzEhNC"
	PubKeyData  string = "rsa MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC57qC/BeoYcM6ijazuaCdJkbT8pvPpFEDVzf9ZQ9axswXU3mywSOaR3wflriSjmvRfUNs/BAjshgtJqgviUXx7lE5aG9mcUyvomyFFpfCR2l2Lvow0H8y7JoL6yxMSQf8gpAcaQzPB8dsfGe+DqA+5wjxXPOhC1QUcllt08yBB3wIDAQAB"
	Signature   string = "lsOsGOrY0rrs4A2CaJ3FzKLU5jx41d/Dw7gxQLUDPC4KMq6Cd3hyjZN6B8BbCDHBcZCFSd+sKvUbmM+ZCM1D6OrqYGvoRLTZJjWqbUsHRS7PkmIUWToxWxe0qo+tq5K/aYoDPJ+o6fRYTnUGILkN5+pQ8NquJqviLPCvBJVpKCo="
)

func TestCreateError(t *testing.T) {
	res := createError("foobar", 400)
	assert.Equal(t, 400, res.StatusCode)
	assert.Equal(t, "{\n  \"error\": \"foobar\"\n}", res.Body)
	assert.Len(t, res.Headers, 1)

	res = createError("", 501)
	assert.Equal(t, 501, res.StatusCode)
	assert.Equal(t, "{\n  \"error\": \"\"\n}", res.Body)
	assert.Len(t, res.Headers, 1)
}

func TestCreateOutput(t *testing.T) {
	data := map[string]string{
		"foo": "123",
		"bar": "foo",
	}

	res := createOutput(data, 200)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "{\n  \"bar\": \"foo\",\n  \"foo\": \"123\"\n}", res.Body)
	assert.Len(t, res.Headers, 1)
}

func TestValidateSignature(t *testing.T) {
	var req events.APIGatewayV2HTTPRequest
	var hashData = "foobar data test"

	req = events.APIGatewayV2HTTPRequest{
		Headers: map[string]string{
			"authorization": "Bearer " + Signature,
		},
	}
	assert.True(t, validateSignature(req.Headers["authorization"], PubKeyData, hashData))

	req = events.APIGatewayV2HTTPRequest{
		Headers: map[string]string{
			"authorization": "Bearer " + Signature,
		},
	}
	assert.False(t, validateSignature(req.Headers["authorization"], "false data", hashData))

	req = events.APIGatewayV2HTTPRequest{
		Headers: map[string]string{
			"authorization": "Bearer " + Signature,
		},
	}
	assert.False(t, validateSignature(req.Headers["authorization"], PubKeyData, hashData+"falsefalse"))

	req = events.APIGatewayV2HTTPRequest{
		Headers: map[string]string{
			"authorization": "ADSAFAFAF",
		},
	}
	assert.False(t, validateSignature(req.Headers["authorization"], PubKeyData, hashData))

	req = events.APIGatewayV2HTTPRequest{
		Headers: map[string]string{
			"authorization": "Bearer *&^(&^%(^&#@%$%)@$%@!$^@$^)@!",
		},
	}
	assert.False(t, validateSignature(req.Headers["authorization"], PubKeyData, hashData))

	req = events.APIGatewayV2HTTPRequest{
		Headers: map[string]string{
			"authorization": "",
		},
	}
	assert.False(t, validateSignature(req.Headers["authorization"], PubKeyData, hashData))

	req = events.APIGatewayV2HTTPRequest{
		Headers: map[string]string{},
	}
	assert.False(t, validateSignature(req.Headers["authorization"], PubKeyData, hashData))
}
