package main

import (
	"encoding/json"
	"log"
	"strconv"

	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	"github.com/bitmaelum/key-resolver-go/internal/http"
	"github.com/bitmaelum/key-resolver-go/organisation"
)

type organisationUploadBody struct {
	PublicKey   bmcrypto.PubKey         `json:"public_key"`
	Proof       proofofwork.ProofOfWork `json:"proof"`
	Validations []string                `json:"validations"`
}

func GetOrganisationHash(hash string, _ http.Request) *http.Response {
	repo := organisation.GetResolveRepository()
	info, err := repo.Get(hash)
	if err != nil && err != organisation.ErrNotFound {
		log.Print(err)
		return http.CreateError("hash not found", 404)
	}

	if info == nil {
		log.Print(err)
		return http.CreateError("hash not found", 404)
	}

	data := http.RawJSONOut{
		"hash":          info.Hash,
		"public_key":    info.PubKey,
		"validations":   info.Validations,
		"serial_number": info.Serial,
	}

	return http.CreateOutput(data, 200)
}

func PostOrganisationHash(hash string, req http.Request) *http.Response {
	repo := organisation.GetResolveRepository()
	current, err := repo.Get(hash)
	if err != nil && err != organisation.ErrNotFound {
		log.Print(err)
		return http.CreateError("error while posting record", 500)
	}

	uploadBody := &organisationUploadBody{}
	err = json.Unmarshal([]byte(req.Body), uploadBody)
	if err != nil {
		log.Print(err)
		return http.CreateError("invalid data", 400)
	}

	if !validateOrganisationBody(*uploadBody) {
		return http.CreateError("invalid data", 400)
	}

	if current == nil {
		// Does not exist yet
		return createOrganisation(hash, *uploadBody)
	}

	// Try update
	return updateOrganisation(*uploadBody, req, current)
}

func DeleteOrganisationHash(hash string, req http.Request) *http.Response {
	repo := organisation.GetResolveRepository()
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

func updateOrganisation(uploadBody organisationUploadBody, req http.Request, current *organisation.ResolveInfoType) *http.Response {
	if !req.ValidateSignature(current.PubKey, current.Hash+strconv.FormatUint(current.Serial, 10)) {
		return http.CreateError("unauthenticated", 401)
	}

	repo := organisation.GetResolveRepository()
	res, err := repo.Update(current, uploadBody.PublicKey.String(), uploadBody.Proof.String(), uploadBody.Validations)

	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while updating: ", 500)
	}

	return http.CreateOutput("updated", 200)
}

func createOrganisation(hash string, uploadBody organisationUploadBody) *http.Response {
	if !uploadBody.Proof.IsValid() {
		return http.CreateError("incorrect proof-of-work", 401)
	}

	repo := organisation.GetResolveRepository()
	res, err := repo.Create(hash, uploadBody.PublicKey.String(), uploadBody.Proof.String(), uploadBody.Validations)

	if err != nil || !res {
		log.Print(err)
		return http.CreateError("error while creating: ", 500)
	}

	return http.CreateOutput("created", 201)
}

func validateOrganisationBody(_ organisationUploadBody) bool {
	// PubKey and proof are already validated through the JSON marshalling
	return true
}
