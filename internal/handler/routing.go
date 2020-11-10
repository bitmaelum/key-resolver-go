package handler

import (
	"encoding/json"
	"log"
	"net"
	"strconv"

	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/key-resolver-go/internal/http"
	"github.com/bitmaelum/key-resolver-go/routing"
)

type routingUploadBody struct {
	PublicKey *bmcrypto.PubKey `json:"public_key"`
	Routing   string           `json:"routing"`
}

func GetRoutingHash(hash string, _ http.Request) *http.Response {
	repo := routing.GetResolveRepository()
	info, err := repo.Get(hash)
	if err != nil && err != routing.ErrNotFound {
		log.Print(err)
		return http.CreateError("hash not found", 404)
	}

	if info == nil {
		log.Print(err)
		return http.CreateError("hash not found", 404)
	}

	data := http.RawJSONOut{
		"hash":          info.Hash,
		"routing":       info.Routing,
		"public_key":    info.PubKey,
		"serial_number": info.Serial,
	}

	return http.CreateOutput(data, 200)
}

func PostRoutingHash(hash string, req http.Request) *http.Response {
	repo := routing.GetResolveRepository()
	current, err := repo.Get(hash)
	if err != nil && err != routing.ErrNotFound {
		log.Print(err)
		return http.CreateError("error while posting record", 500)
	}

	uploadBody := &routingUploadBody{}
	err = json.Unmarshal([]byte(req.Body), uploadBody)
	if err != nil {
		log.Print(err)
		return http.CreateError("invalid data", 400)
	}

	if !validateRoutingBody(*uploadBody) {
		return http.CreateError("invalid data", 400)
	}

	if current == nil {
		// Does not exist yet
		return createRouting(hash, *uploadBody)
	}

	// Try update
	return updateRouting(*uploadBody, req, current)
}

func updateRouting(uploadBody routingUploadBody, req http.Request, current *routing.ResolveInfoType) *http.Response {
	if !req.ValidateSignature(current.PubKey, current.Hash+strconv.FormatUint(current.Serial, 10)) {
		return http.CreateError("unauthenticated", 401)
	}

	repo := routing.GetResolveRepository()
	res, err := repo.Update(current, uploadBody.Routing, uploadBody.PublicKey.String())

	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while updating: ", 500)
	}

	return http.CreateOutput("updated", 200)
}

func createRouting(hash string, uploadBody routingUploadBody) *http.Response {
	repo := routing.GetResolveRepository()
	res, err := repo.Create(hash, uploadBody.Routing, uploadBody.PublicKey.String())

	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while creating: ", 500)
	}

	return http.CreateOutput("created", 201)
}

func DeleteRoutingHash(hash string, req http.Request) *http.Response {
	repo := routing.GetResolveRepository()
	current, err := repo.Get(hash)
	if err != nil {
		log.Print(err)
		return http.CreateError("error while fetching record", 500)
	}

	if current == nil {
		return http.CreateError("cannot find record", 404)
	}

	if !req.ValidateSignature(current.PubKey, current.Hash+strconv.FormatUint(current.Serial, 10)) {
		return http.CreateError("unauthenticated", 401)
	}

	res, err := repo.Delete(current.Hash)
	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while deleting record", 500)
	}

	return http.CreateOutput("ok", 200)
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
