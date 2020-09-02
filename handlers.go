package main

import (
	"github.com/aws/aws-lambda-go/events"
	"github.com/bitmaelum/key-resolver-go/resolver"
)

func getHash(hash string, req events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	repo := resolver.GetResolveRepository()
	info, err := repo.Get(hash)
	if err != nil {
		return createError("hash not found", 404)
	}

	data := jsonOut{
		"hash":       info.Hash,
		"server":     info.Server,
		"public_key": info.PubKey,
	}

	out := createOutput(data, 200)
	headers := map[string]string{}
	headers["Content-Type"] = "text/html"
	out.Headers = headers

	return out
}

func postHash(hash string, req events.APIGatewayV2HTTPRequest) *events.APIGatewayV2HTTPResponse {
	repo := resolver.GetResolveRepository()
	current, err := repo.Get(hash)
	if err != nil {
		return createError("error while posting record", 500)
	}

	var res bool
	if current == nil {
		if !validatePow(req, current) {
			return createError("unauthenticated (pow)", 401)
		}

		res, err = repo.Create("hash", "ServeR-2222", "pubasdfasfdsafdsafakey")
	} else {
		if !validateSignature(req, current) {
			return createError("unauthenticated", 401)
		}

		res, err = repo.Update(current, "ServeR=3333", "pubasdfasfdsafdsafakey")
	}

	if err != nil || res == false {
		return createError("error while updating: "+err.Error(), 500)
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
		return createError("error while deleting record", 500)
	}

	return createOutput("ok", 200)
}
