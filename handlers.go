package main

import (
	"encoding/json"
	"github.com/aws/aws-lambda-go/events"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	"github.com/bitmaelum/key-resolver-go/resolver"
	"log"
)

const (
	// NoOrgHash is the SHA256 of an empty string. Meaning there is no organisation.
	NoOrgHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

type UploadBody struct {
	PublicKey bmcrypto.PubKey         `json:"public_key"`
	Routing   string                  `json:"routing"`
	Proof     proofofwork.ProofOfWork `json:"proof"`
	LocalHash string                  `json:"local_hash"`
	OrgHash   string                  `json:"org_hash"`
}

func getHash(hash string, _ events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	repo := resolver.GetResolveRepository()
	info, err := repo.Get(hash)
	if err != nil && err != resolver.ErrNotFound {
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

func postHash(hash string, req events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	repo := resolver.GetResolveRepository()
	current, err := repo.Get(hash)
	if err != nil && err != resolver.ErrNotFound {
		log.Print(err)
		return createError("error while posting record", 500)
	}

	uploadBody := &UploadBody{}
	err = json.Unmarshal([]byte(req.Body), uploadBody)
	if err != nil {
		log.Print(err)
		return createError("invalid data", 400)
	}

	if current == nil {
		// Does not exist yet
		return createAccount(hash, *uploadBody)
	}

	// Try update
	return updateAccount(*uploadBody, req, current)
}

func updateAccount(uploadBody UploadBody, req events.APIGatewayV2HTTPRequest, current *resolver.ResolveInfoType) *events.APIGatewayV2HTTPResponse {
	if !validateSignature(req, current) {
		return createError("unauthenticated", 401)
	}

	repo := resolver.GetResolveRepository()
	res, err := repo.Update(current, uploadBody.Routing, uploadBody.PublicKey.String())

	if err != nil || res == false {
		log.Print(err)
		return createError("error while updating: ", 500)
	}

	return createOutput("updated", 200)
}

func createAccount(hash string, uploadBody UploadBody) *events.APIGatewayV2HTTPResponse {
	if !uploadBody.Proof.IsValid() {
		return createError("incorrect proof-of-work", 401)
	}

	// HAH! We don't know if it's an organisation or not...:/

	repo := resolver.GetResolveRepository()
	res, err := repo.Create(hash, uploadBody.Routing, uploadBody.PublicKey.String(), uploadBody.Proof.String())

	if err != nil || res == false {
		log.Print(err)
		return createError("error while creating: ", 500)
	}

	return createOutput("created", 201)
}

func deleteHash(hash string, req events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	repo := resolver.GetResolveRepository()
	current, err := repo.Get(hash)
	if err != nil {
		log.Print(err)
		return createError("error while fetching record", 500)
	}

	if current == nil {
		return createError("cannot find record", 404)
	}

	if !validateSignature(req, current) {
		return createError("unauthenticated", 401)
	}

	res, err := repo.Delete(current.Hash)
	if err != nil || res == false {
		log.Print(err)
		return createError("error while deleting record", 500)
	}

	return createOutput("ok", 200)
}
