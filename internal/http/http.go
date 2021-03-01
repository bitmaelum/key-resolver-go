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
	"github.com/gorilla/mux"
)

type Headers struct {
	Headers map[string]string
}

func NewHeaders() Headers {
	return Headers{
		Headers: make(map[string]string),
	}
}

func (h *Headers) Set(key, value string) {
	h.Headers[strings.ToLower(key)] = value
}

func (h *Headers) Get(key string) string {
	return h.Headers[strings.ToLower(key)]
}

func (h *Headers) Has(key string) bool {
	_, ok := h.Headers[strings.ToLower(key)]

	return ok
}

type Request struct {
	Method  string
	URL     string
	Body    string
	Headers Headers
	Params  map[string]string
}

func NewRequest(method, url, body string, params map[string]string) Request {
	return Request{
		Method:  method,
		URL:     url,
		Body:    body,
		Headers: NewHeaders(),
		Params:  params,
	}
}

type Response struct {
	Body       string
	StatusCode int
	Headers    Headers
}

func NewResponse(statusCode int, body string) Response {
	return Response{
		Body:       body,
		StatusCode: statusCode,
		Headers:    NewHeaders(),
	}
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

	resp := NewResponse(statusCode, string(body))
	resp.Headers.Set("content-type", "application/json")

	return &resp
}

func GenerateAuthenticationToken(b []byte, pk bmcrypto.PrivKey) string {
	h := sha256.Sum256(b)
	sig, _ := bmcrypto.Sign(pk, h[:])
	return base64.StdEncoding.EncodeToString(sig)
}

// validateSignature validates a signature based on the authorization header
func (r Request) ValidateAuthenticationToken(pubKey, hashData string) bool {
	if !r.Headers.Has("authorization") {
		return false
	}
	authToken := r.Headers.Get("authorization")
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

// NetReqToReq converts net/http request to our own internal http request format
func NetReqToReq(r http.Request) Request {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return NewRequest("", "", "", nil)
	}

	params := mux.Vars(&r)
	req := NewRequest(r.Method, r.URL.String(), string(b), params)

	// Add headers
	for k, v := range r.Header {
		req.Headers.Set(k, v[0])
	}

	return req
}
