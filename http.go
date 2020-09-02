package main

import (
	"encoding/base64"
	"encoding/json"
	"github.com/aws/aws-lambda-go/events"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/key-resolver-go/resolver"
	"strings"
)

type jsonOut map[string]string

func createError(msg string, statusCode int) *events.APIGatewayV2HTTPResponse {
	errBody := jsonOut{
		"error": msg,
	}
	return createOutput(errBody, statusCode)
}

func createOutput(data interface{}, statusCode int) *events.APIGatewayV2HTTPResponse {
	body, _ := json.MarshalIndent(data, "", "  ")

	return &events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Headers:    nil,
		Body:       string(body),
	}
}

// validateSignature
func validateSignature(req events.APIGatewayV2HTTPRequest, current *resolver.ResolveInfoType) bool {
	auth := req.Headers["authorization"]
	if len(auth) <= 6 || strings.ToUpper(auth[0:7]) != "BEARER " {
		return false
	}
	requestSignature, err := base64.StdEncoding.DecodeString(auth[7:])
	if err != nil {
		return false
	}

	pk, err := bmcrypto.NewPubKey(current.PubKey)
	if err != nil {
		return false
	}

	hashed := []byte(current.Hash + current.Server)
	verified, err := bmcrypto.Verify(*pk, hashed, requestSignature)
	if err != nil {
		return false
	}

	return verified
}
