// Copyright (c) 2020 BitMaelum Authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package reservation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"

	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
)

// RemoteRepository allows you to fetch reservations from a remote server (the keyserver)
type RemoteRepository struct {
	c       *http.Client
	baseUrl string
}

// NewRemoteRepository creates a new repository for fetching reservations through HTTP
func NewRemoteRepository(baseUrl string, client *http.Client) ReservationRepository {
	if client == nil {
		client = http.DefaultClient
	}

	return &RemoteRepository{
		c:       client,
		baseUrl: baseUrl,
	}
}

// IsValidated will check if a hash has a DNS entry with the correct value
func (r RemoteRepository) IsValidated(h hash.Hash, pk *bmcrypto.PubKey) (bool, error) {
	domains, err := r.GetDomains(h)
	if err != nil {
		fmt.Println("Is Validated: errored: ", err)
		return false, err
	}

	fmt.Println("Is Validated: domain count: ", domains)

	// Not reserved
	if len(domains) == 0 {
		return true, err
	}

	for _, domain := range domains {
		entries, err := net.LookupTXT("_bitmaelum." + domain)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry == pk.Fingerprint() {
				return true, nil
			}
		}
	}

	// No domain found that verifies
	return false, nil
}

// IsReserved will return true when the hash is a reserved hash
func (r RemoteRepository) IsReserved(h hash.Hash) (bool, error) {
	d, err := r.GetDomains(h)
	if err != nil {
		return false, err
	}

	fmt.Println("Is Reserved: domain count: ", d)

	return len(d) > 0, nil
}

// GetDomains will return the domains for the given reserved hash, or empty slice when not reserved
func (r RemoteRepository) GetDomains(h hash.Hash) ([]string, error) {
	url := r.baseUrl + h.String()

	var domains = make([]string, 100)

	response, err := r.c.Get(url)
	if err != nil {
		return nil, errors.New("not found")
	}

	if response.StatusCode == 404 {
		return nil, errors.New("not found")
	}

	if response.StatusCode == 200 {
		res, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Printf("cannot get body response from remote resolver: %s", err)
			return nil, errors.New("not found")
		}

		err = json.Unmarshal(res, &domains)
		if err != nil {
			log.Printf("cannot unmarshal resolve body: %s", err)
			return nil, errors.New("not found")
		}

		return domains, nil
	}

	return nil, errors.New("not found")
}
