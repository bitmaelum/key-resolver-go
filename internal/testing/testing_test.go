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

package testing

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadTestKey(t *testing.T) {
	priv, pub, err := ReadTestKey("../../testdata/key-7.json")
	assert.NoError(t, err)
	assert.Equal(t, priv.String(), "ed25519 MC4CAQAwBQYDK2VwBCIEIApsDq5uwKSUNlmw9z3u63CeNdrfDgBOkJRmvM6gvQj3")
	assert.Equal(t, pub.String(), "ed25519 MCowBQYDK2VwAyEA1xbVcwtwUx9EFnvZltYd7qz1FxwJOOugkkA9vHYxoQM=")

	priv, pub, err = ReadTestKey("../does-not-exist.json")
	assert.Error(t, err)
	assert.Nil(t, priv)
	assert.Nil(t, pub)
}
