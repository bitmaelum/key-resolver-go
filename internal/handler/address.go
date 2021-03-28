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
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	"github.com/bitmaelum/key-resolver-go/internal/address"
	"github.com/bitmaelum/key-resolver-go/internal/http"
	"github.com/bitmaelum/key-resolver-go/internal/reservation"
)

type addressUploadBody struct {
	UserHash  hash.Hash                `json:"user_hash"`
	OrgHash   hash.Hash                `json:"org_hash"`
	PublicKey *bmcrypto.PubKey         `json:"public_key"`
	RoutingID string                   `json:"routing_id,omitempty"`
	Proof     *proofofwork.ProofOfWork `json:"proof"`
	RedirHash string                   `json:"redir_hash,omitempty"`
}

var (
	// MaxRedirectDepth is the maximum depth or redirection.
	MaxRedirectDepth = 10
)

var (
	MinimumProofBitsAddress = 27
	routeIDRegex            = regexp.MustCompile("[a-f0-9]{64}")
)

func GetAddressHash(hash hash.Hash, _ http.Request) *http.Response {
	info, httpErr := recursiveGet(hash, MaxRedirectDepth)
	if httpErr != nil {
		return httpErr
	}

	data := http.RawJSONOut{
		"hash":          info.Hash,
		"public_key":    info.PubKey,
		"serial_number": info.Serial,
		"proof":         info.Proof,
	}

	// Add optional items
	if info.RedirHash != "" {
		data["redirect_hash"] = info.RedirHash
	}
	if info.RoutingID != "" {
		data["routing_id"] = info.RoutingID
	}

	return http.CreateOutput(data, 200)
}

func PostAddressHash(addrHash hash.Hash, req http.Request) *http.Response {
	uploadBody := &addressUploadBody{}
	err := json.Unmarshal([]byte(req.Body), uploadBody)
	if err != nil {
		log.Print(err)
		return http.CreateError("invalid data", 400)
	}

	httpErr := validateAddress(addrHash, uploadBody)
	if httpErr != nil {
		return httpErr
	}

	repo := address.GetResolveRepository()
	current, err := repo.Get(addrHash.String())
	if err != nil && err != address.ErrNotFound {
		log.Print(err)
		return http.CreateError("error while posting record", 500)
	}

	// Check if redirection is confirming our rules (maxdepth and cyclic dependency)
	httpErr = validateRedirection(uploadBody.RedirHash)
	if httpErr != nil {
		return httpErr
	}

	// Address exists already, update it
	if current != nil {
		return updateAddress(*uploadBody, req, current)
	}

	// Check if the address is a reserved address and validated correctly
	ok, err := reservation.ReservationService.IsValidated(addrHash, uploadBody.PublicKey)
	if !ok || err != nil {
		return http.CreateError("reserved address", 400)
	}

	// Address does not exist, create it
	return createAddress(addrHash, *uploadBody)
}

func DeleteAddressHash(addrHash hash.Hash, req http.Request) *http.Response {
	repo := address.GetResolveRepository()
	current, err := repo.Get(addrHash.String())
	if err != nil {
		log.Print(err)
		return http.CreateError("error while fetching record", 500)
	}

	if current == nil || current.Deleted {
		log.Print(err)
		return http.CreateError("cannot find record", 404)
	}

	if !req.ValidateAuthenticationToken(current.PubKey, current.Hash+current.RoutingID+strconv.FormatUint(current.Serial, 10)) {
		return http.CreateError("unauthenticated", 401)
	}

	res, err := repo.Delete(current.Hash)
	if err != nil || !res {
		return http.CreateError("error while deleting record", 500)
	}

	return http.CreateMessage("address has been deleted", 200)
}

func SoftDeleteAddressHash(addrHash hash.Hash, req http.Request) *http.Response {
	repo := address.GetResolveRepository()
	current, err := repo.Get(addrHash.String())
	if err != nil {
		return http.CreateError("error while fetching record", 500)
	}

	if !req.ValidateAuthenticationToken(current.PubKey, current.Hash+current.RoutingID+strconv.FormatUint(current.Serial, 10)) {
		return http.CreateError("unauthenticated", 401)
	}

	if current == nil || current.Deleted {
		return http.CreateError("cannot find record", 404)
	}

	res, err := repo.SoftDelete(current.Hash)
	if err != nil || !res {
		return http.CreateError("error while deleting record", 500)
	}

	return http.CreateMessage("address has been soft-deleted", 200)
}

func SoftUndeleteAddressHash(addrHash hash.Hash, req http.Request) *http.Response {
	repo := address.GetResolveRepository()
	current, err := repo.Get(addrHash.String())
	if err != nil {
		return http.CreateError("error while fetching record", 500)
	}

	if current == nil {
		return http.CreateError("cannot find record", 404)
	}

	if !current.Deleted {
		return http.CreateError("not deleted", 400)
	}

	if !req.ValidateAuthenticationToken(current.PubKey, current.Hash+current.RoutingID+strconv.FormatUint(current.Serial, 10)) {
		return http.CreateError("unauthenticated", 401)
	}

	res, err := repo.SoftUndelete(current.Hash)
	if err != nil || !res {
		return http.CreateError("error while undeleting record", 500)
	}

	return http.CreateMessage("address has been undeleted", 200)
}

func GetKeyStatus(hash hash.Hash, req http.Request) *http.Response {
	fp, ok := req.Params["fingerprint"]
	if !ok {
		return http.CreateError("not found", 404)
	}

	repo := address.GetResolveRepository()
	ks, err := repo.GetKeyStatus(hash.String(), fp)
	if err != nil {
		return http.CreateError("not found", 404)
	}

	var messageMap = map[address.KeyStatus]string{
		address.KSNormal:      "normal",
		address.KSCompromised: "compromised",
	}

	msg, ok := messageMap[ks]
	if !ok {
		msg = "unknown"
	}

	return http.CreateMessage(msg, 200)
}

func SetKeyStatus(hash hash.Hash, req http.Request) *http.Response {
	fp, ok := req.Params["fingerprint"]
	if !ok {
		return http.CreateError("not found", 404)
	}

	type setKeyRequestBody struct {
		Status string `json:"status"`
	}

	body := &setKeyRequestBody{}
	if req.Body != "" {
		err := json.Unmarshal([]byte(req.Body), body)
		if err != nil {
			log.Print(err)
			return http.CreateError("invalid body data", 400)
		}
	}

	ks, err := address.StringToKeyStatus(body.Status)
	if err != nil {
		return http.CreateError("invalid status", 400)
	}

	repo := address.GetResolveRepository()
	err = repo.SetKeyStatus(hash.String(), fp, ks)
	if err != nil {
		return http.CreateError("error while updating", 400)
	}

	return http.CreateMessage("key status has been updated", 200)
}

func updateAddress(uploadBody addressUploadBody, req http.Request, current *address.ResolveInfoType) *http.Response {
	if !req.ValidateAuthenticationToken(current.PubKey, current.Hash+current.RoutingID+strconv.FormatUint(current.Serial, 10)) {
		return http.CreateError("unauthenticated", 401)
	}

	repo := address.GetResolveRepository()
	res, err := repo.Update(current, uploadBody.RoutingID, uploadBody.PublicKey, uploadBody.RedirHash)

	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while updating: ", 500)
	}

	return http.CreateMessage("address has been updated", 200)
}

func createAddress(addrHash hash.Hash, uploadBody addressUploadBody) *http.Response {
	// Validate proof of work
	if !uploadBody.Proof.IsValid() || uploadBody.Proof.Data != addrHash.String() {
		return http.CreateError("incorrect proof-of-work", 401)
	}

	// Check minimum number of work bits
	if uploadBody.Proof.Bits < MinimumProofBitsAddress {
		return http.CreateError(fmt.Sprintf("proof-of-work too weak (need %d bits)", MinimumProofBitsAddress), 401)
	}

	repo := address.GetResolveRepository()
	res, err := repo.Create(addrHash.String(), uploadBody.RoutingID, uploadBody.PublicKey, uploadBody.Proof.String(), uploadBody.RedirHash)
	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while creating: ", 500)
	}

	return http.CreateMessage("address has been created", 201)
}

func validateAddress(addrHash hash.Hash, body *addressUploadBody) *http.Response {
	// Check if the user + org hash matches the address hash. This will verify the address inside the organisation
	if !addrHash.Verify(body.UserHash, body.OrgHash) {
		return http.CreateError("hash verification failed", 400)
	}

	// Check routing ID if exists
	routing := strings.ToLower(body.RoutingID)
	if routing != "" && !routeIDRegex.Match([]byte(routing)) {
		return http.CreateError("invalid routing id", 400)
	}

	// Can't be an organisational address and not have a redirect hash
	if !body.OrgHash.IsEmpty() && body.RedirHash == "" {
		return http.CreateError("organisation account must use redirection", 400)
	}

	// Can't be an organisational address and have a routing ID  (redirects only)
	if !body.OrgHash.IsEmpty() && body.RoutingID != "" {
		return http.CreateError("cannot add routing to an organisation account", 400)
	}

	return nil
}

func validateRedirection(addrHash string) *http.Response {
	// No redir. So it's always ok
	if addrHash == "" {
		return nil
	}

	// Test redirection on one level below, since we want to add a new entry on top.
	_, err := recursiveGet(hash.Hash(addrHash), MaxRedirectDepth-1)
	return err
}

func recursiveGet(h hash.Hash, depth int) (*address.ResolveInfoType, *http.Response) {
	curDepth := 0
	var cyclicHashes []string

	for {
		repo := address.GetResolveRepository()
		info, err := repo.Get(h.String())
		if err != nil && err != address.ErrNotFound {
			return nil, http.CreateError("hash not found", 404)
		}

		if info == nil || info.Deleted {
			return nil, http.CreateError("hash not found", 404)
		}

		// Not redirect, so we can break our loop
		if info.RedirHash == "" {
			return info, nil
		}

		// Increase depth and see if we are allowed to continue
		curDepth += 1
		if curDepth >= depth {
			return nil, http.CreateError("maximum redirection reached", 400)
		}

		// Check for cyclic dependency
		for i := range cyclicHashes {
			if cyclicHashes[i] == h.String() {
				return nil, http.CreateError("cyclic dependency detected", 400)
			}
		}
		cyclicHashes = append(cyclicHashes, h.String())

		// Next item
		h = hash.Hash(info.RedirHash)
	}
}
