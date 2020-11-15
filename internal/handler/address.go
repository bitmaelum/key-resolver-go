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
	"regexp"
	"strconv"
	"strings"

	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	"github.com/bitmaelum/key-resolver-go/internal/address"
	"github.com/bitmaelum/key-resolver-go/internal/http"
	"github.com/bitmaelum/key-resolver-go/internal/organisation"
)

type addressUploadBody struct {
	UserHash  hash.Hash                `json:"user_hash"`
	OrgHash   hash.Hash                `json:"org_hash"`
	OrgToken  string                   `json:"org_token,omitempty"`
	PublicKey *bmcrypto.PubKey         `json:"public_key"`
	RoutingID string                   `json:"routing_id"`
	Proof     *proofofwork.ProofOfWork `json:"proof"`
}

var (
	minimumProofBits = 22
)

type organizationRequestBody struct {
	UserHash         hash.Hash `json:"user_hash,omitempty"`
	OrganizationHash hash.Hash `json:"org_hash,omitempty"`
}

func GetAddressHash(hash hash.Hash, _ http.Request) *http.Response {
	repo := address.GetResolveRepository()
	info, err := repo.Get(hash.String())
	if err != nil && err != address.ErrNotFound {
		log.Print(err)
		return http.CreateError("hash not found", 404)
	}

	if info == nil {
		log.Print(err)
		return http.CreateError("hash not found", 404)
	}

	data := http.RawJSONOut{
		"hash":          info.Hash,
		"routing_id":    info.RoutingID,
		"public_key":    info.PubKey,
		"serial_number": info.Serial,
		"proof":         info.Proof,
	}

	return http.CreateOutput(data, 200)
}

func PostAddressHash(addrHash hash.Hash, req http.Request) *http.Response {
	repo := address.GetResolveRepository()
	current, err := repo.Get(addrHash.String())
	if err != nil && err != address.ErrNotFound {
		log.Print(err)
		return http.CreateError("error while posting record", 500)
	}

	uploadBody := &addressUploadBody{}
	err = json.Unmarshal([]byte(req.Body), uploadBody)
	if err != nil {
		log.Print(err)
		return http.CreateError("invalid data", 400)
	}

	if !validateAddressBody(addrHash, *uploadBody) {
		return http.CreateError("invalid data", 400)
	}

	// Check org token
	if uploadBody.OrgToken != "" && !validateOrgToken(uploadBody.OrgToken, addrHash, uploadBody.OrgHash, uploadBody.RoutingID) {
		return http.CreateError("cannot validate organisation token", 400)
	}

	if current == nil {
		// Does not exist yet
		return createAddress(addrHash, *uploadBody)
	}

	// Try update
	return updateAddress(*uploadBody, req, current)
}

func DeleteAddressHash(addrHash hash.Hash, req http.Request) *http.Response {
	requestBody := &organizationRequestBody{}

	if req.Body != "" {
		err := json.Unmarshal([]byte(req.Body), requestBody)
		if err != nil {
			log.Print(err)
			return http.CreateError("invalid body data", 400)
		}
	}

	if requestBody.OrganizationHash != "" {
		return deleteAddressHashByOrganization(addrHash, requestBody, req)
	}

	return deleteAddressHashByOwner(addrHash, req)
}

func deleteAddressHashByOwner(addrHash hash.Hash, req http.Request) *http.Response {
	repo := address.GetResolveRepository()
	current, err := repo.Get(addrHash.String())
	if err != nil {
		log.Print(err)
		return http.CreateError("error while fetching record", 500)
	}

	if current == nil {
		return http.CreateError("cannot find record", 404)
	}

	if !req.ValidateSignature(current.PubKey, current.Hash+current.RoutingID+strconv.FormatUint(current.Serial, 10)) {
		return http.CreateError("unauthenticated", 401)
	}

	res, err := repo.Delete(current.Hash)
	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while deleting record", 500)
	}

	return http.CreateOutput("ok", 200)
}

func deleteAddressHashByOrganization(addrHash hash.Hash, organizationInfo *organizationRequestBody, req http.Request) *http.Response {
	addressRepo := address.GetResolveRepository()
	currentAddress, err := addressRepo.Get(addrHash.String())
	if err != nil {
		log.Print(err)
		return http.CreateError("error while fetching address record", 500)
	}

	orgRepo := organisation.GetResolveRepository()
	currentOrg, err := orgRepo.Get(organizationInfo.OrganizationHash.String())
	if err != nil {
		log.Print(err)
		return http.CreateError("error while fetching organization record", 500)
	}

	if currentAddress == nil {
		return http.CreateError("cannot find address record", 404)
	}

	if currentOrg == nil {
		return http.CreateError("cannot find organization record", 404)
	}

	// Checks if the user hash + org hash matches the hash to be deleted
	if !addrHash.Verify(organizationInfo.UserHash, organizationInfo.OrganizationHash) {
		return http.CreateError("error validating address", 401)
	}

	if !req.ValidateSignature(currentOrg.PubKey, currentAddress.Hash+strconv.FormatUint(currentAddress.Serial, 10)) {
		return http.CreateError("unauthenticated", 401)
	}

	res, err := addressRepo.Delete(currentAddress.Hash)
	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while deleting address record", 500)
	}

	return http.CreateOutput("ok", 200)
}

func updateAddress(uploadBody addressUploadBody, req http.Request, current *address.ResolveInfoType) *http.Response {
	if !req.ValidateSignature(current.PubKey, current.Hash+current.RoutingID+strconv.FormatUint(current.Serial, 10)) {
		return http.CreateError("unauthenticated", 401)
	}

	repo := address.GetResolveRepository()
	res, err := repo.Update(current, uploadBody.RoutingID, uploadBody.PublicKey.String())

	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while updating: ", 500)
	}

	return http.CreateOutput("updated", 200)
}

func createAddress(addrHash hash.Hash, uploadBody addressUploadBody) *http.Response {
	if !uploadBody.Proof.IsValid() {
		return http.CreateError("incorrect proof-of-work", 401)
	}

	// Sanity check to see if the proof given actually matches our wanted data and minimum bits
	if uploadBody.Proof.Data != addrHash.String() || uploadBody.Proof.Bits < minimumProofBits {
		return http.CreateError("incorrect proof-of-work", 401)
	}

	repo := address.GetResolveRepository()
	res, err := repo.Create(addrHash.String(), uploadBody.RoutingID, uploadBody.PublicKey.String(), uploadBody.Proof.String())
	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while creating: ", 500)
	}

	return http.CreateOutput("created", 201)
}

// Validate the incoming body
func validateAddressBody(addrHash hash.Hash, body addressUploadBody) bool {
	// PubKey and Pow are already validated through the JSON marshalling

	// Check if the user + org hash matches the address hash
	if !addrHash.Verify(body.UserHash, body.OrgHash) {
		log.Print("verify hash failed")
		return false
	}

	// When specifying an organisation, we need an organisation token
	if !body.OrgHash.IsEmpty() && body.OrgToken == "" {
		log.Print("need token for org")
		return false
	}

	// Can't specify token when no org is needed
	if body.OrgHash.IsEmpty() && body.OrgToken != "" {
		log.Print("don't need token for non-org")
		return false
	}

	// Check routing
	re, err := regexp.Compile("^[a-z0-9]{64}$")
	if err != nil {
		log.Print("check routing ID failed")
		return false
	}

	routing := strings.ToLower(body.RoutingID)
	return re.Match([]byte(routing))
}

// Validate the organisation token
func validateOrgToken(token string, addr hash.Hash, orgHash hash.Hash, routingID string) bool {
	// Load org Info
	repo := organisation.GetResolveRepository()
	oi, err := repo.Get(orgHash.String())
	if err != nil {
		return false
	}
	pubKey, err := bmcrypto.NewPubKey(oi.PubKey)
	if err != nil {
		return false
	}

	return address.VerifyInviteToken(token, addr, routingID, *pubKey)
}
