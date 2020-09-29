package main

import (
	"math/rand"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

var version = "v0.0.1"

var logo = "<pre> ____  _ _   __  __            _<br>" +
	"|  _ \\(_) | |  \\/  |          | |   " + version + "<br>" +
	"| |_) |_| |_| \\  / | __ _  ___| |_   _ _ __ ___<br>" +
	"|  _ <| | __| |\\/| |/ _` |/ _ \\ | | | | '_ ` _ \\<br>" +
	"| |_) | | |_| |  | | (_| |  __/ | |_| | | | | | |<br>" +
	"|____/|_|\\__|_|  |_|\\__,_|\\___|_|\\__,_|_| |_| |_|<br>" +
	"<br>" +
	"   P r i v a c y   i s   y o u r s   a g a i n<br>" +
	"</pre>"

// HandleRequest checks the incoming route and calls the correct handler for it
func HandleRequest(req events.APIGatewayV2HTTPRequest) (*events.APIGatewayV2HTTPResponse, error) {
	if req.RouteKey == "GET /" {
		return getIndex(req), nil
	}

	hash := strings.ToLower(req.PathParameters["hash"])
	if len(hash) != 64 {
		return createError("Incorrect hash address", 400), nil
	}

	switch req.RouteKey {

	// @TODO: root endpoints are legacy. Remove ASAPs
	case "GET /{hash}":
		return getAddressHash(hash, req), nil
	case "DELETE /{hash}":
		return deleteAddressHash(hash, req), nil
	case "POST /{hash}":
		return postAddressHash(hash, req), nil

	// Address endpoints
	case "GET /address/{hash}":
		return getAddressHash(hash, req), nil
	case "DELETE /address/{hash}":
		return deleteAddressHash(hash, req), nil
	case "POST /address/{hash}":
		return postAddressHash(hash, req), nil

	// Routing endpoints
	case "GET /routing/{hash}":
		return getRoutingHash(hash, req), nil
	case "DELETE /routing/{hash}":
		return deleteRoutingHash(hash, req), nil
	case "POST /routing/{hash}":
		return postRoutingHash(hash, req), nil

	// Organisation endpoints
	case "GET /organisation/{hash}":
		return getOrganisationHash(hash, req), nil
	case "DELETE /organisation/{hash}":
		return deleteOrganisationHash(hash, req), nil
	case "POST /organisation/{hash}":
		return postOrganisationHash(hash, req), nil
	}

	return createError("Forbidden", 403), nil
}

func getIndex(_ events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	headers := map[string]string{}
	headers["Content-Type"] = "text/html"

	resp := &events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Headers:    headers,
		Body:       logo,
	}

	return resp
}

func main() {
	rand.Seed(time.Now().UnixNano())
	lambda.Start(HandleRequest)
}
