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

package internal

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"

	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
)

// @TODO: Make this dynamic
const baseReservedUrl = "https://resolver.bitmaelum.org/reserved/"

func getDomainReservations(hash hash.Hash) ([]string, error) {
	// call /reserved/<hash>
	client := http.DefaultClient
	url := baseReservedUrl + hash.String()

	var domains = make([]string, 100)

	response, err := client.Get(url)
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

func CheckReservations(h hash.Hash, pk *bmcrypto.PubKey) bool {
	domains, err := getDomainReservations(h)
	if err != nil {
		// Error while fetching domains
		return false
	}

	// Not reserved
	if len(domains) == 0 {
		return true
	}

	for _, domain := range domains {
		entries, err := net.LookupTXT("_bitmaelum." + domain)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry == pk.Fingerprint() {
				return true
			}
		}
	}

	// No domain found for verification
	return false
}
