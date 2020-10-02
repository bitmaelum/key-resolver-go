package main

import (
	"encoding/json"
	"log"
	"net"
	"strconv"

	"github.com/aws/aws-lambda-go/events"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/key-resolver-go/routing"
)

type routingUploadBody struct {
	PublicKey *bmcrypto.PubKey `json:"public_key"`
	Routing   string           `json:"routing"`
}

func getRoutingHash(hash string, _ events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	repo := routing.GetResolveRepository()
	info, err := repo.Get(hash)
	if err != nil && err != routing.ErrNotFound {
		log.Print(err)
		return createError("hash not found", 404)
	}

	if info == nil {
		log.Print(err)
		return createError("hash not found", 404)
	}

	data := rawJSONOut{
		"hash":          info.Hash,
		"routing":       info.Routing,
		"public_key":    info.PubKey,
		"serial_number": info.Serial,
	}

	return createOutput(data, 200)
}

func postRoutingHash(hash string, req events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	repo := routing.GetResolveRepository()
	current, err := repo.Get(hash)
	if err != nil && err != routing.ErrNotFound {
		log.Print(err)
		return createError("error while posting record", 500)
	}

	uploadBody := &routingUploadBody{}
	err = json.Unmarshal([]byte(req.Body), uploadBody)
	if err != nil {
		log.Print(err)
		return createError("invalid data", 400)
	}

	if !validateRoutingBody(*uploadBody) {
		return createError("invalid data", 400)
	}

	if current == nil {
		// Does not exist yet
		return createRouting(hash, *uploadBody)
	}

	// Try update
	return updateRouting(*uploadBody, req.Headers["authorization"], current)
}

func updateRouting(uploadBody routingUploadBody, authToken string, current *routing.ResolveInfoType) *events.APIGatewayV2HTTPResponse {
	if !validateSignature(authToken, current.PubKey, current.Hash+strconv.FormatUint(current.Serial, 10)) {
		return createError("unauthenticated", 401)
	}

	repo := routing.GetResolveRepository()
	res, err := repo.Update(current, uploadBody.Routing, uploadBody.PublicKey.String())

	if err != nil || !res {
		log.Print(err)
		return createError("error while updating: ", 500)
	}

	return createOutput("updated", 200)
}

func createRouting(hash string, uploadBody routingUploadBody) *events.APIGatewayV2HTTPResponse {
	repo := routing.GetResolveRepository()
	res, err := repo.Create(hash, uploadBody.Routing, uploadBody.PublicKey.String())

	if err != nil || !res {
		log.Print(err)
		return createError("error while creating: ", 500)
	}

	return createOutput("created", 201)
}

func deleteRoutingHash(hash string, req events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	repo := routing.GetResolveRepository()
	current, err := repo.Get(hash)
	if err != nil {
		log.Print(err)
		return createError("error while fetching record", 500)
	}

	if current == nil {
		return createError("cannot find record", 404)
	}

	if !validateSignature(req.Headers["authorization"], current.PubKey, current.Hash+strconv.FormatUint(current.Serial, 10)) {
		return createError("unauthenticated", 401)
	}

	res, err := repo.Delete(current.Hash)
	if err != nil || !res {
		log.Print(err)
		return createError("error while deleting record", 500)
	}

	return createOutput("ok", 200)
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
