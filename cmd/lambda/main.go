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
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/bitmaelum/key-resolver-go/internal"
	"github.com/bitmaelum/key-resolver-go/internal/apigateway"
	"github.com/bitmaelum/key-resolver-go/internal/handler"
	"github.com/bitmaelum/key-resolver-go/internal/http"
)

// HandleRequest checks the incoming route and calls the correct handler for it
func HandleRequest(req events.APIGatewayV2HTTPRequest) (*events.APIGatewayV2HTTPResponse, error) {
	fmt.Println(req.RouteKey)

	if req.RouteKey == "GET /" {
		return getIndex(req), nil
	}

	if req.RouteKey == "GET /config.json" {
		return getConfig(req), nil
	}


	h, err := hash.NewFromHash(req.PathParameters["hash"])
	if err != nil {
		resp := http.CreateError("Incorrect hash address", 400)
		return apigateway.HTTPToResp(resp), nil
	}

	var httpResp *http.Response
	httpReq := apigateway.ReqToHTTP(&req)

	switch req.RouteKey {
	// Address endpoints
	case "GET /address/{hash}":
		httpResp = handler.GetAddressHash(*h, *httpReq)
	case "DELETE /address/{hash}":
		httpResp = handler.DeleteAddressHash(*h, *httpReq)
	case "POST /address/{hash}":
		httpResp = handler.PostAddressHash(*h, *httpReq)

	// Routing endpoints
	case "GET /routing/{hash}":
		httpResp = handler.GetRoutingHash(*h, *httpReq)
	case "DELETE /routing/{hash}":
		httpResp = handler.DeleteRoutingHash(*h, *httpReq)
	case "POST /routing/{hash}":
		httpResp = handler.PostRoutingHash(*h, *httpReq)

	// Organisation endpoints
	case "GET /organisation/{hash}":
		httpResp = handler.GetOrganisationHash(*h, *httpReq)
	case "DELETE /organisation/{hash}":
		httpResp = handler.DeleteOrganisationHash(*h, *httpReq)
	case "POST /organisation/{hash}":
		httpResp = handler.PostOrganisationHash(*h, *httpReq)
	}

	if httpResp == nil {
		httpResp = http.CreateError("Forbidden", 403)
	}

	return apigateway.HTTPToResp(httpResp), nil
}

func getIndex(_ events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	headers := map[string]string{}
	headers["Content-Type"] = "text/html"

	resp := &events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Headers:    headers,
		Body:       "<pre>" + strings.Replace(internal.Logo, "\n", "<br>", -1) + "</pre>",
	}

	return resp
}

func getConfig(_ events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	headers := map[string]string{}
	headers["Content-Type"] = "application/json"

	data := http.RawJSONOut{
		"proof_of_work": http.RawJSONOut{
			"address":      handler.MinimumProofBitsAddress,
			"organisation": handler.MinimumProofBitsOrganisation,
		},
	}

	strJson, _ := json.MarshalIndent(data, "", "  ")

	resp := &events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Headers:    headers,
		Body:       string(strJson),
	}

	return resp
}


func main() {
	rand.Seed(time.Now().UnixNano())
	lambda.Start(HandleRequest)
}
