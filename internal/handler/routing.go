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

package handler

import (
	"encoding/json"
	"log"
	"net"
	"strconv"

	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/bitmaelum/key-resolver-go/internal/http"
	"github.com/bitmaelum/key-resolver-go/internal/routing"
)

type routingUploadBody struct {
	PublicKey *bmcrypto.PubKey `json:"public_key"`
	Routing   string           `json:"routing"`
}

func GetRoutingHash(routingHash hash.Hash, _ http.Request) *http.Response {
	repo := routing.GetResolveRepository()
	info, err := repo.Get(routingHash.String())
	if err != nil && err != routing.ErrNotFound {
		log.Print(err)
		return http.CreateError("hash not found", 404)
	}

	if info == nil {
		log.Print(err)
		return http.CreateError("hash not found", 404)
	}

	data := http.RawJSONOut{
		"hash":          info.Hash,
		"routing":       info.Routing,
		"public_key":    info.PubKey,
		"serial_number": info.Serial,
	}

	return http.CreateOutput(data, 200)
}

func PostRoutingHash(routingHash hash.Hash, req http.Request) *http.Response {
	repo := routing.GetResolveRepository()
	current, err := repo.Get(routingHash.String())
	if err != nil && err != routing.ErrNotFound {
		log.Print(err)
		return http.CreateError("error while posting record", 500)
	}

	uploadBody := &routingUploadBody{}
	err = json.Unmarshal([]byte(req.Body), uploadBody)
	if err != nil {
		log.Print(err)
		return http.CreateError("invalid data", 400)
	}

	if !validateRoutingBody(*uploadBody) {
		return http.CreateError("invalid data", 400)
	}

	if current == nil {
		// Does not exist yet
		return createRouting(routingHash, *uploadBody)
	}

	// Try update
	return updateRouting(*uploadBody, req, current)
}

func updateRouting(uploadBody routingUploadBody, req http.Request, current *routing.ResolveInfoType) *http.Response {
	if !req.ValidateAuthenticationToken(current.PubKey, current.Hash+strconv.FormatUint(current.Serial, 10)) {
		return http.CreateError("unauthenticated", 401)
	}

	repo := routing.GetResolveRepository()
	res, err := repo.Update(current, uploadBody.Routing, uploadBody.PublicKey.String())

	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while updating: ", 500)
	}

	return http.CreateOutput("updated", 200)
}

func createRouting(routingHash hash.Hash, uploadBody routingUploadBody) *http.Response {
	repo := routing.GetResolveRepository()
	res, err := repo.Create(routingHash.String(), uploadBody.Routing, uploadBody.PublicKey.String())

	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while creating: ", 500)
	}

	return http.CreateOutput("created", 201)
}

func DeleteRoutingHash(routingHash hash.Hash, req http.Request) *http.Response {
	repo := routing.GetResolveRepository()
	current, err := repo.Get(routingHash.String())
	if err != nil {
		log.Print(err)
		return http.CreateError("error while fetching record", 500)
	}

	if current == nil {
		return http.CreateError("cannot find record", 404)
	}

	if !req.ValidateAuthenticationToken(current.PubKey, current.Hash+strconv.FormatUint(current.Serial, 10)) {
		return http.CreateError("unauthenticated", 401)
	}

	res, err := repo.Delete(current.Hash)
	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while deleting record", 500)
	}

	return http.CreateOutput("ok", 200)
}

func validateRoutingBody(body routingUploadBody) bool {
	// PubKey is already validated through the JSON marshalling

	_, _, err := net.SplitHostPort(body.Routing)
	if err != nil {
		body.Routing += ":2424"
	}

	// Check routing
	_, err = net.ResolveTCPAddr("tcp", body.Routing)
	if err != nil {
		log.Print(err)
		return false
	}

	return true
}
