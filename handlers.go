package main

import (
	"encoding/json"
	"github.com/aws/aws-lambda-go/events"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	"github.com/bitmaelum/key-resolver-go/resolver"
	"log"
)

type KeyUpload struct {
	PublicKey bmcrypto.PubKey         `json:"public_key"`
	Address   string                  `json:"address"`
	Pow       proofofwork.ProofOfWork `json:"pow"`
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
		"server":     info.Server,
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

	reqBody := &KeyUpload{}
	err = json.Unmarshal([]byte(req.Body), reqBody)
	if err != nil {
		log.Print(err)
		return createError("invalid data", 400)
	}

	var res bool
	if current == nil {
		if !reqBody.Pow.IsValid() {
			return createError("unauthenticated (pow)", 401)
		}

		res, err = repo.Create(hash, reqBody.Address, reqBody.PublicKey.String(), reqBody.Pow.String())
	} else {
		if !validateSignature(req, current) {
			return createError("unauthenticated", 401)
		}

		res, err = repo.Update(current, reqBody.Address, reqBody.PublicKey.String())
	}

	if err != nil || res == false {
		log.Print(err)
		return createError("error while updating: ", 500)
	}

	// Create returns 201, update returns 200
	statusCode := 200
	if current == nil {
		statusCode = 201
	}
	return createOutput("ok", statusCode)
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
