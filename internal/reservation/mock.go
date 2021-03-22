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
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
)

type domainEntry struct {
	Hash   hash.Hash
	Domain string
}

// MockRepository is a simple repository that allows you to easily mock reserved accounts and organisations
type MockRepository struct {
	Entries []domainEntry
	DNS     map[string]string
}

func NewMockRepository() *MockRepository {
	return &MockRepository{
		Entries: []domainEntry{},
		DNS:     make(map[string]string),
	}
}

// Adds a new entry to the mock reservations
func (m *MockRepository) AddEntry(h hash.Hash, domains []string) {
	for i := range domains {
		m.Entries = append(m.Entries, domainEntry{
			Hash:   h,
			Domain: domains[i],
		})
	}
}

// Adds a DNS entry so we can verify
func (m *MockRepository) AddDNS(domain, value string) {
	m.DNS[domain] = value
}

// IsValidated will check if a hash has a DNS entry with the correct value
func (m *MockRepository) IsValidated(h hash.Hash, pk *bmcrypto.PubKey) (bool, error) {
	domains, err := m.GetDomains(h)
	if err != nil {
		return false, err
	}

	// NO domains, so not a reserved hash
	if len(domains) == 0 {
		return true, nil
	}

	for i := range domains {
		if m.DNS[domains[i]] == pk.Fingerprint() {
			return true, nil
		}
	}

	return false, nil
}

// IsReserved will return true when the hash is a reserved hash
func (m *MockRepository) IsReserved(h hash.Hash) (bool, error) {
	d, err := m.GetDomains(h)
	if err != nil {
		return false, err
	}

	return len(d) > 0, nil
}

// GetDomains will return the domains for the given reserved hash, or empty slice when not reserved
func (m *MockRepository) GetDomains(h hash.Hash) ([]string, error) {
	var domains []string

	for i := range m.Entries {
		if m.Entries[i].Hash.String() == h.String() {
			domains = append(domains, m.Entries[i].Domain)
		}
	}

	return domains, nil
}
