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
	"github.com/aws/aws-lambda-go/events"
	"github.com/bitmaelum/key-resolver-go/internal/http"
)

// ReqToHTTP converts a api gateway http request to our internal http request
func ReqToHTTP(req *events.APIGatewayV2HTTPRequest) *http.Request {
	httpReq := http.Request{
		Method:  req.RequestContext.HTTP.Method,
		URL:     req.RequestContext.HTTP.Path,
		Body:    req.Body,
		Headers: make(map[string][]string),
	}

	// Add headers
	for k, v := range req.Headers {
		httpReq.Headers[k] = []string{v}
	}

	return &httpReq
}

// HTTPToResp converts an internal http response to an api gateway http response
func HTTPToResp(resp *http.Response) *events.APIGatewayV2HTTPResponse {
	return &events.APIGatewayV2HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: resp.Body,
	}
}
