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

package address

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	dynamock "github.com/gusaul/go-dynamock"
	"github.com/stretchr/testify/assert"
)

var (
	mock *dynamock.DynaMock
)

func TestGet(t *testing.T) {
	var client dynamodbiface.DynamoDBAPI
	client, mock = dynamock.New()
	resolver := NewDynamoDBResolver(client, "mock_address_table")

	ri, err := resolver.Get("cf99b895f350b77585881438ab38a935e68c9c7409c5adaad23fb17572ca1ea2")
	assert.Error(t, err)
	assert.Nil(t, ri)

	result := dynamodb.GetItemOutput{
		Item: map[string]*dynamodb.AttributeValue{
			"hash":       {S: aws.String("cf99b895f350b77585881438ab38a935e68c9c7409c5adaad23fb17572ca1ea2")},
			"routing":    {S: aws.String("12345678")},
			"public_key": {S: aws.String("pubkey")},
			"proof":      {S: aws.String("proof")},
			"sn":         {N: aws.String("42")},
		},
	}

	expectKey := map[string]*dynamodb.AttributeValue{
		"hash": {
			S: aws.String("cf99b895f350b77585881438ab38a935e68c9c7409c5adaad23fb17572ca1ea2"),
		},
	}
	mock.ExpectGetItem().ToTable("mock_address_table").WithKeys(expectKey).WillReturns(result)
	ri, err = resolver.Get("cf99b895f350b77585881438ab38a935e68c9c7409c5adaad23fb17572ca1ea2")
	assert.NoError(t, err)
	assert.Equal(t, "cf99b895f350b77585881438ab38a935e68c9c7409c5adaad23fb17572ca1ea2", ri.Hash)
	assert.Equal(t, "12345678", ri.RoutingID)
	assert.Equal(t, "proof", ri.Proof)
	assert.Equal(t, "pubkey", ri.PubKey)
	assert.Equal(t, uint64(42), ri.Serial)

	// No record found
	ri, err = resolver.Get("000000000000000000000000000000000000000009c5adaad23fb17572ca1ea2")
	assert.Error(t, err)
	assert.Nil(t, ri)

	// No record found
	result = dynamodb.GetItemOutput{
		Item: nil,
	}

	mock.ExpectGetItem().ToTable("mock_address_table").WithKeys(expectKey).WillReturns(result)
	ri, err = resolver.Get("cf99b895f350b77585881438ab38a935e68c9c7409c5adaad23fb17572ca1ea2")
	assert.Error(t, err)
	assert.Nil(t, ri)
}

func TestDelete(t *testing.T) {
	var client dynamodbiface.DynamoDBAPI
	client, mock = dynamock.New()
	resolver := NewDynamoDBResolver(client, "mock_address_table")

	// No record found
	result := dynamodb.DeleteItemOutput{
		Attributes: nil,
	}

	mock.ExpectDeleteItem().ToTable("mock_address_table").WillReturns(result)
	ok, err := resolver.Delete("cf99b895f350b77585881438ab38a935e68c9c7409c5adaad23fb17572ca1ea2")
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, err = resolver.Delete("cf99b895f350b77585881438ab38a935e68c9c7409c5adaad23fb17572ca1ea2")
	assert.Error(t, err)
	assert.False(t, ok)
}

func TestCreate(t *testing.T) {
	var client dynamodbiface.DynamoDBAPI
	client, mock = dynamock.New()
	resolver := NewDynamoDBResolver(client, "mock_address_table")

	timeNow = func() time.Time {
		return time.Date(2010, 05, 10, 12, 34, 56, 0, time.UTC)
	}

	result := dynamodb.PutItemOutput{}

	items := map[string]*dynamodb.AttributeValue{
		"hash":       {S: aws.String("cf99b895f350b77585881438ab38a935e68c9c7409c5adaad23fb17572ca1ea2")},
		"proof":      {S: aws.String("proof")},
		"public_key": {S: aws.String("pubkey")},
		"routing":    {S: aws.String("12345678")},
		"sn":         {N: aws.String("1273494896000000000")},
	}
	mock.ExpectPutItem().ToTable("mock_address_table").WithItems(items).WillReturns(result)
	ok, err := resolver.Create("cf99b895f350b77585881438ab38a935e68c9c7409c5adaad23fb17572ca1ea2", "12345678", "pubkey", "proof")
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestUpdate(t *testing.T) {
	var client dynamodbiface.DynamoDBAPI
	client, mock = dynamock.New()
	resolver := NewDynamoDBResolver(client, "mock_address_table")

	expectKey := map[string]*dynamodb.AttributeValue{
		"hash": {
			S: aws.String("cf99b895f350b77585881438ab38a935e68c9c7409c5adaad23fb17572ca1ea2"),
		},
	}
	mock.ExpectUpdateItem().ToTable("mock_address_table").WithKeys(expectKey)

	info := &ResolveInfoType{
		Hash:      "cf99b895f350b77585881438ab38a935e68c9c7409c5adaad23fb17572ca1ea2",
		RoutingID: "12345678",
		PubKey:    "pubkey",
		Proof:     "proof",
		Serial:    1273494896000000000,
	}
	ok, err := resolver.Update(info, "555555555", "pubkey222")
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestResolver(t *testing.T) {
	r := GetResolveRepository()
	assert.NotNil(t, r)
}
