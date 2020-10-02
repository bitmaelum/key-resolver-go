package testing

import (
	"encoding/json"
	"io/ioutil"

	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
)

func ReadTestKey(p string) (*bmcrypto.PrivKey, *bmcrypto.PubKey, error) {
	data, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, nil, err
	}

	type jsonKeyType struct {
		PrivKey bmcrypto.PrivKey `json:"private_key"`
		PubKey  bmcrypto.PubKey  `json:"public_key"`
	}

	v := &jsonKeyType{}
	err = json.Unmarshal(data, &v)
	if err != nil {
		return nil, nil, err
	}

	return &v.PrivKey, &v.PubKey, nil
}
