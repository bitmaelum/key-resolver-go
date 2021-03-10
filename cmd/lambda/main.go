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
	"math/rand"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/bitmaelum/key-resolver-go/internal"
	"github.com/bitmaelum/key-resolver-go/internal/apigateway"
	"github.com/bitmaelum/key-resolver-go/internal/handler"
	"github.com/bitmaelum/key-resolver-go/internal/http"
)

type HandlerFunc func(hash.Hash, http.Request) *http.Response

var handlerMapping = map[string]HandlerFunc{
	"GET /address/{hash}":                       handler.GetAddressHash,
	"POST /address/{hash}/delete":               handler.SoftDeleteAddressHash,
	"POST /address/{hash}/undelete":             handler.SoftUndeleteAddressHash,
	"GET /address/{hash}/status/{fingerprint}":  handler.GetKeyStatus,
	"POST /address/{hash}/status/{fingerprint}": handler.SetKeyStatus,
	"DELETE /address/{hash}":                    handler.DeleteAddressHash,
	"POST /address/{hash}":                      handler.PostAddressHash,
	"GET /routing/{hash}":                       handler.GetRoutingHash,
	"DELETE /routing/{hash}":                    handler.DeleteRoutingHash,
	"POST /routing/{hash}":                      handler.PostRoutingHash,
	"GET /organisation/{hash}":                  handler.GetOrganisationHash,
	"POST /organisation/{hash}/delete":          handler.SoftDeleteOrganisationHash,
	"POST /organisation/{hash}/undelete":        handler.SoftUndeleteOrganisationHash,
	"DELETE /organisation/{hash}":               handler.DeleteOrganisationHash,
	"POST /organisation/{hash}":                 handler.PostOrganisationHash,
}

// HandleRequest checks the incoming route and calls the correct handler for it
func HandleRequest(req events.APIGatewayV2HTTPRequest) (*events.APIGatewayV2HTTPResponse, error) {
	logMetric(req.RouteKey)

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

	// Check mapping and call correct handler func
	f, ok := handlerMapping[req.RouteKey]
	if ok {
		httpResp = f(*h, *httpReq)
	}

	if httpResp == nil {
		httpResp = http.CreateError("Forbidden", 403)
	}

	return apigateway.HTTPToResp(httpResp), nil
}

/**
 * Increase metrics
 */
func logMetric(path string) {
	input := &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]*string{
			"#count": aws.String("count"),
		},
		TableName:           aws.String("prometheus"),
		UpdateExpression:    aws.String("SET #count = #count + 1"),
		Key: map[string]*dynamodb.AttributeValue{
			"path": {S: aws.String(path)},
		},
	}

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	dyna := dynamodb.New(sess)

	// Update address record
	_, _ = dyna.UpdateItem(input)
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
