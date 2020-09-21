package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/aws/aws-lambda-go/events"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"log"
	"strings"
)

type jsonOut map[string]string

// createError creates an error message json structure
func createError(msg string, statusCode int) *events.APIGatewayV2HTTPResponse {
	errBody := jsonOut{
		"error": msg,
	}
	return createOutput(errBody, statusCode)
}

// createOutput creates json output for data
func createOutput(data interface{}, statusCode int) *events.APIGatewayV2HTTPResponse {
	body, _ := json.MarshalIndent(data, "", "  ")

	return &events.APIGatewayV2HTTPResponse{
		StatusCode: statusCode,
		Headers:    nil,
		Body:       string(body),
	}
}

// validateSignature validates a signature based on the authorization header
func validateSignature(req events.APIGatewayV2HTTPRequest, pubKey, hashData string) bool {
	log.Printf("req: %#v", req)
	auth := req.Headers["authorization"]
	if len(auth) <= 6 || strings.ToUpper(auth[0:7]) != "BEARER " {
		return false
	}
	requestSignature, err := base64.StdEncoding.DecodeString(auth[7:])
	if err != nil {
		log.Printf("err: %s", err)
		return false
	}

	pk, err := bmcrypto.NewPubKey(pubKey)
	if err != nil {
		log.Printf("err: %s", err)
		return false
	}

	hash := sha256.Sum256([]byte(hashData))
	verified, err := bmcrypto.Verify(*pk, hash[:], requestSignature)
	if err != nil {
		log.Printf("err: %s", err)
		return false
	}

	return verified
}
