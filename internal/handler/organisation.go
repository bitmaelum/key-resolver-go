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
	"strconv"

	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	"github.com/bitmaelum/key-resolver-go/internal/http"
	"github.com/bitmaelum/key-resolver-go/internal/organisation"
)

type organisationUploadBody struct {
	PublicKey   *bmcrypto.PubKey         `json:"public_key"`
	Proof       *proofofwork.ProofOfWork `json:"proof"`
	Validations []string                 `json:"validations"`
}

func GetOrganisationHash(orgHash hash.Hash, _ http.Request) *http.Response {
	repo := organisation.GetResolveRepository()
	info, err := repo.Get(orgHash.String())
	if err != nil && err != organisation.ErrNotFound {
		log.Print(err)
		return http.CreateError("hash not found", 404)
	}

	if info == nil {
		log.Print(err)
		return http.CreateError("hash not found", 404)
	}

	data := http.RawJSONOut{
		"hash":          info.Hash,
		"public_key":    info.PubKey,
		"proof":         info.Proof,
		"validations":   info.Validations,
		"serial_number": info.Serial,
	}

	return http.CreateOutput(data, 200)
}

func PostOrganisationHash(orgHash hash.Hash, req http.Request) *http.Response {
	repo := organisation.GetResolveRepository()
	current, err := repo.Get(orgHash.String())
	if err != nil && err != organisation.ErrNotFound {
		log.Print(err)
		return http.CreateError("error while posting record", 500)
	}

	uploadBody := &organisationUploadBody{}
	err = json.Unmarshal([]byte(req.Body), uploadBody)
	if err != nil {
		log.Print(err)
		return http.CreateError("invalid data", 400)
	}

	if !validateOrganisationBody(*uploadBody) {
		return http.CreateError("invalid data", 400)
	}

	if current == nil {
		// Does not exist yet
		return createOrganisation(orgHash, *uploadBody)
	}

	// Try update
	return updateOrganisation(*uploadBody, req, current)
}

func DeleteOrganisationHash(orgHash hash.Hash, req http.Request) *http.Response {
	repo := organisation.GetResolveRepository()
	current, err := repo.Get(orgHash.String())
	if err != nil {
		log.Print(err)
		return http.CreateError("error while fetching record", 500)
	}

	if current == nil {
		return http.CreateError("cannot find record", 404)
	}

	if !req.ValidateSignature(current.PubKey, current.Hash+strconv.FormatUint(current.Serial, 10)) {
		return http.CreateError("unauthenticated", 401)
	}

	res, err := repo.Delete(current.Hash)
	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while deleting record", 500)
	}

	return http.CreateOutput("ok", 200)
}

func updateOrganisation(uploadBody organisationUploadBody, req http.Request, current *organisation.ResolveInfoType) *http.Response {
	if !req.ValidateSignature(current.PubKey, current.Hash+strconv.FormatUint(current.Serial, 10)) {
		return http.CreateError("unauthenticated", 401)
	}

	repo := organisation.GetResolveRepository()
	res, err := repo.Update(current, uploadBody.PublicKey.String(), uploadBody.Proof.String(), uploadBody.Validations)

	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while updating: ", 500)
	}

	return http.CreateOutput("updated", 200)
}

func createOrganisation(orgHash hash.Hash, uploadBody organisationUploadBody) *http.Response {
	if !uploadBody.Proof.IsValid() {
		return http.CreateError("incorrect proof-of-work", 401)
	}

	// Sanity check to see if the proof given actually matches our wanted data and minimum bits
	if uploadBody.Proof.Data != orgHash.String() || uploadBody.Proof.Bits < minimumProofBits {
		return http.CreateError("incorrect proof-of-work", 401)
	}

	repo := organisation.GetResolveRepository()
	res, err := repo.Create(orgHash.String(), uploadBody.PublicKey.String(), uploadBody.Proof.String(), uploadBody.Validations)

	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while creating: ", 500)
	}

	return http.CreateOutput("created", 201)
}

func validateOrganisationBody(_ organisationUploadBody) bool {
	// PubKey and proof are already validated through the JSON marshalling
	return true
}
