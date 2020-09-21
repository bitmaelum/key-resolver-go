package main

import (
	"encoding/json"
	"github.com/aws/aws-lambda-go/events"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	"github.com/bitmaelum/key-resolver-go/address"
	"log"
)

type addressUploadBody struct {
	PublicKey bmcrypto.PubKey         `json:"public_key"`
	Routing   string                  `json:"routing"`
	Proof     proofofwork.ProofOfWork `json:"proof"`
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

	data := jsonOut{
		"hash":       info.Hash,
		"routing":    info.Routing,
		"public_key": info.PubKey,
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

	if current == nil {
		// Does not exist yet
		return createAddress(hash, *uploadBody)
	}

	// Try update
	return updateAddress(*uploadBody, req, current)
}

func deleteAddressHash(hash string, req events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	repo := address.GetResolveRepository()
	current, err := repo.Get(hash)
	if err != nil {
		log.Print(err)
		return createError("error while fetching record", 500)
	}

	if current == nil {
		return createError("cannot find record", 404)
	}

	if !validateSignature(req, current.PubKey, current.Hash+current.Routing) {
		return createError("unauthenticated", 401)
	}

	res, err := repo.Delete(current.Hash)
	if err != nil || res == false {
		log.Print(err)
		return createError("error while deleting record", 500)
	}

	return createOutput("ok", 200)
}

func updateAddress(uploadBody addressUploadBody, req events.APIGatewayV2HTTPRequest, current *address.ResolveInfoType) *events.APIGatewayV2HTTPResponse {
	if !validateSignature(req, current.PubKey, current.Hash+current.Routing) {
		return createError("unauthenticated", 401)
	}

	repo := address.GetResolveRepository()
	res, err := repo.Update(current, uploadBody.Routing, uploadBody.PublicKey.String())

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
	res, err := repo.Create(hash, uploadBody.Routing, uploadBody.PublicKey.String(), uploadBody.Proof.String())

	if err != nil || res == false {
		log.Print(err)
		return createError("error while creating: ", 500)
	}

	return createOutput("created", 201)
}
