package http

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
)

type Request struct {
	Method  string
	URL     string
	Body    string
	Headers map[string][]string
}

type Response struct {
	Body       string
	StatusCode int
	Headers    map[string][]string
}

type JsonOut map[string]string
type RawJSONOut map[string]interface{}

// CreateError creates an error message json structure
func CreateError(msg string, statusCode int) *Response {
	errBody := JsonOut{
		"error": msg,
	}

	return CreateOutput(errBody, statusCode)
}

// createOutput creates json output for data
func CreateOutput(data interface{}, statusCode int) *Response {
	body, _ := json.MarshalIndent(data, "", "  ")

	h := make(map[string][]string)
	h["Content-Type"] = []string{"application/json"}

	return &Response{
		StatusCode: statusCode,
		Headers:    h,
		Body:       string(body),
	}
}

// validateSignature validates a signature based on the authorization header
func (r Request) ValidateSignature(pubKey, hashData string) bool {
	authTokens, ok := r.Headers["Authorization"]
	authToken := authTokens[0]
	if !ok || len(authToken) <= 6 || strings.ToUpper(authToken[0:7]) != "BEARER " {
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

// NetReqToReq converts net/http request to our own internal http request format
func NetReqToReq(r http.Request) Request {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return Request{}
	}

	h := make(map[string][]string)
	for k, v := range r.Header {
		h[k] = v
	}

	return Request{
		Method:  r.Method,
		URL:     r.URL.String(),
		Body:    string(b),
		Headers: h,
	}
}
