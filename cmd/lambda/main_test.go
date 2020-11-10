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

package main

import (
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/assert"
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
