package handler

import (
	"encoding/json"
	"log"
	"regexp"
	"strconv"
	"strings"

	pkgAddress "github.com/bitmaelum/bitmaelum-suite/pkg/address"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	"github.com/bitmaelum/key-resolver-go/address"
	"github.com/bitmaelum/key-resolver-go/internal/http"
	"github.com/bitmaelum/key-resolver-go/organisation"
)

type addressUploadBody struct {
	UserHash  string                  `json:"user_hash"`
	OrgHash   string                  `json:"org_hash"`
	OrgToken  string                  `json:"org_token,omitempty"`
	PublicKey bmcrypto.PubKey         `json:"public_key"`
	RoutingID string                  `json:"routing_id"`
	Proof     proofofwork.ProofOfWork `json:"proof"`
}

type organizationRequestBody struct {
	UserHash         string `json:"user_hash"`
	OrganizationHash string `json:"org_hash"`
}

func GetAddressHash(hash string, _ http.Request) *http.Response {
	repo := address.GetResolveRepository()
	info, err := repo.Get(hash)
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
	}

	return http.CreateOutput(data, 200)
}

func PostAddressHash(addrHash string, req http.Request) *http.Response {
	repo := address.GetResolveRepository()
	current, err := repo.Get(addrHash)
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

func DeleteAddressHash(addrHash string, req http.Request) *http.Response {
	requestBody := &organizationRequestBody{}

	err := json.Unmarshal([]byte(req.Body), requestBody)
	if err != nil {
		log.Print(err)
		return http.CreateError("invalid body data", 400)
	}

	if requestBody.OrganizationHash != "" {
		return deleteAddressHashByOrganization(addrHash, requestBody, req)
	}

	return deleteAddressHashByOwner(addrHash, req)
}

func deleteAddressHashByOwner(addrHash string, req http.Request) *http.Response {
	repo := address.GetResolveRepository()
	current, err := repo.Get(addrHash)
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

func deleteAddressHashByOrganization(addrHash string, organizationInfo *organizationRequestBody, req http.Request) *http.Response {
	addressRepo := address.GetResolveRepository()
	currentAddress, err := addressRepo.Get(addrHash)
	if err != nil {
		log.Print(err)
		return http.CreateError("error while fetching address record", 500)
	}

	orgRepo := organisation.GetResolveRepository()
	currentOrg, err := orgRepo.Get(organizationInfo.OrganizationHash)
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
	if !pkgAddress.VerifyHash(addrHash, organizationInfo.UserHash, organizationInfo.OrganizationHash) {
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

func createAddress(addrHash string, uploadBody addressUploadBody) *http.Response {
	if !uploadBody.Proof.IsValid() {
		return http.CreateError("incorrect proof-of-work", 401)
	}

	repo := address.GetResolveRepository()
	res, err := repo.Create(addrHash, uploadBody.RoutingID, uploadBody.PublicKey.String(), uploadBody.Proof.String())
	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while creating: ", 500)
	}

	return http.CreateOutput("created", 201)
}

// Validate the incoming body
func validateAddressBody(addrHash string, body addressUploadBody) bool {
	// PubKey and Pow are already validated through the JSON marshalling

	// Check if the user + org hash matches the address hash
	if !pkgAddress.VerifyHash(addrHash, body.UserHash, body.OrgHash) {
		return false
	}

	// When specifying an organisation, we need an organisation token
	if body.OrgHash != "" && body.OrgToken == "" {
		return false
	}

	// Can't specify token when no org is needed
	if body.OrgHash == "" && body.OrgToken != "" {
		return false
	}

	// Check routing
	routing := strings.ToLower(body.RoutingID)

	re, err := regexp.Compile("^[a-z0-9]{64}$")
	if err != nil {
		return false
	}

	return re.Match([]byte(routing))
}

// Validate the organisation token
func validateOrgToken(token, addr string, orgHash string, routingID string) bool {
	addrHash, err := pkgAddress.NewHashFromHash(addr)
	if err != nil {
		return false
	}

	// Load org Info
	repo := organisation.GetResolveRepository()
	oi, err := repo.Get(orgHash)
	if err != nil {
		return false
	}
	pubKey, err := bmcrypto.NewPubKey(oi.PubKey)
	if err != nil {
		return false
	}

	return address.VerifyInviteToken(token, addrHash, routingID, *pubKey)
}
