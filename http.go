package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
)

type jsonOut map[string]string
type rawJSONOut map[string]interface{}

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
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(body),
	}
}

// validateSignature validates a signature based on the authorization header
func validateSignature(authToken string, pubKey, hashData string) bool {
	if len(authToken) <= 6 || strings.ToUpper(authToken[0:7]) != "BEARER " {
		return false
	}
	requestSignature, err := base64.StdEncoding.DecodeString(authToken[7:])
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
