package main

import (
	"encoding/json"
	"github.com/aws/aws-lambda-go/events"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/key-resolver-go/routing_resolver"
	"log"
)

type RoutingUploadBody struct {
	PublicKey bmcrypto.PubKey         `json:"public_key"`
	Routing   string                  `json:"routing"`
}

func getRoutingHash(hash string, _ events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	repo := routing_resolver.GetResolveRepository()
	info, err := repo.Get(hash)
	if err != nil && err != routing_resolver.ErrNotFound {
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

func postRoutingHash(hash string, req events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	repo := routing_resolver.GetResolveRepository()
	current, err := repo.Get(hash)
	if err != nil && err != routing_resolver.ErrNotFound {
		log.Print(err)
		return createError("error while posting record", 500)
	}

	uploadBody := &RoutingUploadBody{}
	err = json.Unmarshal([]byte(req.Body), uploadBody)
	if err != nil {
		log.Print(err)
		return createError("invalid data", 400)
	}

	if current == nil {
		// Does not exist yet
		return createRouting(hash, *uploadBody)
	}

	// Try update
	return updateRouting(*uploadBody, req, current)
}

func updateRouting(uploadBody RoutingUploadBody, req events.APIGatewayV2HTTPRequest, current *routing_resolver.ResolveInfoType) *events.APIGatewayV2HTTPResponse {
	if !validateSignature(req, current) {
		return createError("unauthenticated", 401)
	}

	repo := routing_resolver.GetResolveRepository()
	res, err := repo.Update(current, uploadBody.Routing, uploadBody.PublicKey.String())

	if err != nil || res == false {
		log.Print(err)
		return createError("error while updating: ", 500)
	}

	return createOutput("updated", 200)
}

func createRouting(hash string, uploadBody RoutingUploadBody) *events.APIGatewayV2HTTPResponse {
	repo := routing_resolver.GetResolveRepository()
	res, err := repo.Create(hash, uploadBody.Routing, uploadBody.PublicKey.String())

	if err != nil || res == false {
		log.Print(err)
		return createError("error while creating: ", 500)
	}

	return createOutput("created", 201)
}

func deleteRoutingHash(hash string, req events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	repo := routing_resolver.GetResolveRepository()
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
