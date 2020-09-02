package main

import (
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"strings"
)

var version = "v0.0.2"

var logo = " ____  _ _   __  __            _\n" +
	"|  _ \\(_) | |  \\/  |          | |\n" +
	"| |_) |_| |_| \\  / | __ _  ___| |_   _ _ __ ___\n" +
	"|  _ <| | __| |\\/| |/ _` |/ _ \\ | | | | '_ ` _ \\\n" +
	"| |_) | | |_| |  | | (_| |  __/ | |_| | | | | | |\n" +
	"|____/|_|\\__|_|  |_|\\__,_|\\___|_|\\__,_|_| |_| |_|\n" +
	"\n" +
	"   P r i v a c y   i s   y o u r s   a g a i n\n" +
	"\n"

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
	// path := strings.Join(strings.Split(req.RequestContext.HTTP.Path, "/")[2:], "^")
	// req.RequestContext.HTTP.Path = path
	//
	// s, _ := json.MarshalIndent(&req, "", "  ")
	//
	// resp := &events.APIGatewayV2HTTPResponse{
	// 	StatusCode: 200,
	// 	Headers:    nil,
	// 	Body:       string(s),
	// }
	// return resp

	logo = strings.Replace(logo, "\n", "<br>", -1)
	body := fmt.Sprintf("<pre>%s\n\nKey resolver %s</pre>", logo, version)

	headers := map[string]string{}
	headers["Content-Type"] = "text/html"

	resp := &events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Headers:    headers,
		Body:       body,
	}

	return resp
}

func main() {
	lambda.Start(HandleRequest)
}
