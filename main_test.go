package main

import (
	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHandleRequestIndex(t *testing.T) {
	req := &events.APIGatewayV2HTTPRequest{
		RouteKey: "GET /",
	}

	res, err := HandleRequest(*req)
	assert.NoError(t, err)

	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "text/html", res.Headers["Content-Type"])
}

func TestHandleNoHash(t *testing.T) {
	req := &events.APIGatewayV2HTTPRequest{
		RouteKey: "GET /account/foobar",
		PathParameters: map[string]string{
			"hash": "incorrect hash",
		},
	}

	res, err := HandleRequest(*req)
	assert.NoError(t, err)

	assert.Equal(t, 400, res.StatusCode)
	assert.Equal(t, "application/json", res.Headers["Content-Type"])
	assert.Equal(t, "{\n  \"error\": \"Incorrect hash address\"\n}", res.Body)
}

func TestHandleRequest404(t *testing.T) {
	req := &events.APIGatewayV2HTTPRequest{
		RouteKey: "GET /foo/bar/unknown",
		PathParameters: map[string]string{
			"hash": "49AA67181F4A3176F9B65605390BB81126E8FF1F6D03B1BD220C53E7A6B36D3E",
		},
	}

	res, err := HandleRequest(*req)
	assert.NoError(t, err)

	assert.Equal(t, 403, res.StatusCode)
	assert.Equal(t, "application/json", res.Headers["Content-Type"])
	assert.Equal(t, "{\n  \"error\": \"Forbidden\"\n}", res.Body)
}
