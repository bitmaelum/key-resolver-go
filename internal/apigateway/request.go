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
