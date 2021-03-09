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

package apigateway

import (
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/bitmaelum/key-resolver-go/internal/http"
	"github.com/stretchr/testify/assert"
)

func TestReqToHTTP(t *testing.T) {
	req := &events.APIGatewayV2HTTPRequest{
		Version:  "latest",
		RouteKey: "foo",
		RawPath:  "/foo",
		Headers: map[string]string{
			"header-1": "value-1",
			"header-2": "value-2",
		},
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RouteKey:  "foo",
			AccountID: "1234",
			Stage:     "test",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:    "GET",
				Path:      "/foobar",
				Protocol:  "https",
				SourceIP:  "127.2.3.4",
				UserAgent: "gotest",
			},
		},
		Body: "body",
	}

	httpReq := ReqToHTTP(req)
	assert.Equal(t, httpReq.Body, "body")
	assert.Equal(t, httpReq.URL, "/foobar")
	assert.Equal(t, httpReq.Method, "GET")
	assert.Len(t, httpReq.Headers.Headers, 2)
	assert.Equal(t, "value-1", httpReq.Headers.Get("header-1"))
	assert.Equal(t, "value-2", httpReq.Headers.Get("header-2"))
}

func TestHTTPToResp(t *testing.T) {
	resp := &http.Response{
		Body:       "this is body",
		StatusCode: 123,
		Headers: http.Headers{
			Headers: map[string]string{
				"h1": "v1",
				"h2": "v2",
			},
		},
	}

	apigwResp := HTTPToResp(resp)
	assert.Equal(t, 123, apigwResp.StatusCode)
	assert.Equal(t, "this is body", apigwResp.Body)
	assert.Equal(t, "application/json", apigwResp.Headers["Content-Type"])
	assert.Len(t, apigwResp.Headers, 1)
}
