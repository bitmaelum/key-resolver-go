package main

import (
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"strings"
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
	case "GET /{hash}":
		return getHash(hash, req), nil
	case "DELETE /{hash}":
		return deleteHash(hash, req), nil
	case "POST /{hash}":
		return postHash(hash, req), nil
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
	lambda.Start(HandleRequest)
}
