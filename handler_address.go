package main

import (
	"encoding/json"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	pkgAddress "github.com/bitmaelum/bitmaelum-suite/pkg/address"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	"github.com/bitmaelum/key-resolver-go/address"
	"github.com/bitmaelum/key-resolver-go/organisation"
)

type addressUploadBody struct {
	PublicKey bmcrypto.PubKey         `json:"public_key"`
	RoutingID string                  `json:"routing_id"`
	Proof     proofofwork.ProofOfWork `json:"proof"`
}

type organizationRequestBody struct {
	UserHash         string `json:"user_hash"`
	OrganizationHash string `json:"org_hash"`
}

func getAddressHash(hash string, _ events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	repo := address.GetResolveRepository()
	info, err := repo.Get(hash)
	if err != nil && err != address.ErrNotFound {
		log.Print(err)
		return createError("hash not found", 404)
	}

	if info == nil {
		log.Print(err)
		return createError("hash not found", 404)
	}

	data := rawJSONOut{
		"hash":          info.Hash,
		"routing_id":    info.RoutingID,
		"public_key":    info.PubKey,
		"serial_number": info.Serial,
	}

	return createOutput(data, 200)
}

func postAddressHash(hash string, req events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	repo := address.GetResolveRepository()
	current, err := repo.Get(hash)
	if err != nil && err != address.ErrNotFound {
		log.Print(err)
		return createError("error while posting record", 500)
	}

	uploadBody := &addressUploadBody{}
	err = json.Unmarshal([]byte(req.Body), uploadBody)
	if err != nil {
		log.Print(err)
		return createError("invalid data", 400)
	}

	if !validateAddressBody(*uploadBody) {
		return createError("invalid data", 400)
	}

	if current == nil {
		// Does not exist yet
		return createAddress(hash, *uploadBody)
	}

	// Try update
	return updateAddress(*uploadBody, req, current)
}

func deleteAddressHash(hash string, req events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	requestBody := &organizationRequestBody{}
	err := json.Unmarshal([]byte(req.Body), requestBody)
	if err != nil {
		log.Print(err)
		return createError("invalid body data", 400)
	}

	if requestBody.OrganizationHash != "" {
		return deleteAddressHashByOrganization(hash, requestBody, req)
	}

	return deleteAddressHashByOwner(hash, req)
}

func deleteAddressHashByOwner(hash string, req events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	repo := address.GetResolveRepository()
	current, err := repo.Get(hash)
	if err != nil {
		log.Print(err)
		return createError("error while fetching record", 500)
	}

	if current == nil {
		return createError("cannot find record", 404)
	}

	if !validateSignature(req, current.PubKey, current.Hash+current.RoutingID+strconv.FormatUint(current.Serial, 10)) {
		return createError("unauthenticated", 401)
	}

	res, err := repo.Delete(current.Hash)
	if err != nil || res == false {
		log.Print(err)
		return createError("error while deleting record", 500)
	}

	return createOutput("ok", 200)
}

func deleteAddressHashByOrganization(hash string, organizationInfo *organizationRequestBody, req events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	addressRepo := address.GetResolveRepository()
	currentAddress, err := addressRepo.Get(hash)
	if err != nil {
		log.Print(err)
		return createError("error while fetching address record", 500)
	}

	orgRepo := organisation.GetResolveRepository()
	currentOrg, err := orgRepo.Get(organizationInfo.OrganizationHash)
	if err != nil {
		log.Print(err)
		return createError("error while fetching organization record", 500)
	}

	if currentAddress == nil {
		return createError("cannot find address record", 404)
	}

	if currentOrg == nil {
		return createError("cannot find organization record", 404)
	}

	//Checks if the userhash+orghash matches the hash to be deleted
	if !pkgAddress.VerifyHash(hash, organizationInfo.UserHash, organizationInfo.OrganizationHash) {
		return createError("error validating address", 401)
	}

	if !validateSignature(req, currentOrg.PubKey, currentAddress.Hash+strconv.FormatUint(currentAddress.Serial, 10)) {
		return createError("unauthenticated", 401)
	}

	res, err := addressRepo.Delete(currentAddress.Hash)
	if err != nil || res == false {
		log.Print(err)
		return createError("error while deleting address record", 500)
	}

	return createOutput("ok", 200)
}

func updateAddress(uploadBody addressUploadBody, req events.APIGatewayV2HTTPRequest, current *address.ResolveInfoType) *events.APIGatewayV2HTTPResponse {
	if !validateSignature(req, current.PubKey, current.Hash+current.RoutingID+strconv.FormatUint(current.Serial, 10)) {
		return createError("unauthenticated", 401)
	}

	repo := address.GetResolveRepository()
	res, err := repo.Update(current, uploadBody.RoutingID, uploadBody.PublicKey.String())

	if err != nil || res == false {
		log.Print(err)
		return createError("error while updating: ", 500)
	}

	return createOutput("updated", 200)
}

func createAddress(hash string, uploadBody addressUploadBody) *events.APIGatewayV2HTTPResponse {
	if !uploadBody.Proof.IsValid() {
		return createError("incorrect proof-of-work", 401)
	}

	repo := address.GetResolveRepository()
	res, err := repo.Create(hash, uploadBody.RoutingID, uploadBody.PublicKey.String(), uploadBody.Proof.String())
	if err != nil || res == false {
		log.Print(err)
		return createError("error while creating: ", 500)
	}

	return createOutput("created", 201)
}

func validateAddressBody(body addressUploadBody) bool {
	// PubKey and Pow are already validated through the JSON marshalling

	// Check routing
	routing := strings.ToLower(body.RoutingID)

	re, err := regexp.Compile("^[a-z0-9]{64}$")
	if err != nil {
		return false
	}

	if re.Match([]byte(routing)) == false {
		return false
	}

	return true
}
