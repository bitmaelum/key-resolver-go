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

package organisation

import (
	"errors"
	"log"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

type dynamoDbResolver struct {
	C         *dynamodb.DynamoDB
	TableName string
}

// ErrNotFound will be returned when a record we are looking for is not found in the db
var ErrNotFound = errors.New("record not found")

// Record holds a DynamoDB record
type Record struct {
	Hash        string   `dynamodbav:"hash"`
	PublicKey   string   `dynamodbav:"public_key"`
	Proof       string   `dynamodbav:"proof"`
	Validations []string `dynamodbav:"validations"`
	Serial      uint64   `dynamodbav:"sn"`
}

// NewDynamoDBResolver returns a new resolver based on DynamoDB
func NewDynamoDBResolver(client *dynamodb.DynamoDB, tableName string) Repository {
	return &dynamoDbResolver{
		C:         client,
		TableName: tableName,
	}
}

func (r *dynamoDbResolver) Update(info *ResolveInfoType, publicKey, proof string, validations []string) (bool, error) {
	serial := strconv.FormatUint(uint64(time.Now().UnixNano()), 10)

	input := &dynamodb.UpdateItemInput{
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":pk":  {S: aws.String(publicKey)},
			":p":   {S: aws.String(proof)},
			":v":   {SS: aws.StringSlice(validations)},
			":sn":  {N: aws.String(serial)},
			":csn": {N: aws.String(strconv.FormatUint(info.Serial, 10))},
		},
		TableName:           aws.String(r.TableName),
		UpdateExpression:    aws.String("SET proof=:p, public_key=:pk, validations=:v, sn=:sn"),
		ConditionExpression: aws.String("sn = :csn"),
		Key: map[string]*dynamodb.AttributeValue{
			"hash": {S: aws.String(info.Hash)},
		},
	}

	_, err := r.C.UpdateItem(input)
	if err != nil {
		log.Print(err)
		return false, err
	}

	return true, nil
}

func (r *dynamoDbResolver) Create(hash, publicKey, proof string, validations []string) (bool, error) {
	record := Record{
		Hash:        hash,
		PublicKey:   publicKey,
		Proof:       proof,
		Validations: validations,
		Serial:      uint64(time.Now().UnixNano()),
	}

	av, err := dynamodbattribute.MarshalMap(record)
	if err != nil {
		log.Print(err)
		return false, err
	}

	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(r.TableName),
	}

	_, err = r.C.PutItem(input)
	return err == nil, err
}

func (r *dynamoDbResolver) Get(hash string) (*ResolveInfoType, error) {
	result, err := r.C.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(r.TableName),
		Key: map[string]*dynamodb.AttributeValue{
			"hash": {S: aws.String(hash)},
		},
	})
	// Error while fetching record
	if err != nil {
		log.Print(err)
		return nil, err
	}

	// Item not found
	if result.Item == nil {
		return nil, ErrNotFound
	}

	record := Record{}
	err = dynamodbattribute.UnmarshalMap(result.Item, &record)
	if err != nil {
		log.Print(err)
		return nil, ErrNotFound
	}

	return &ResolveInfoType{
		Hash:        record.Hash,
		PubKey:      record.PublicKey,
		Proof:       record.Proof,
		Validations: record.Validations,
		Serial:      record.Serial,
	}, nil
}

func (r *dynamoDbResolver) Delete(hash string) (bool, error) {
	_, err := r.C.DeleteItem(&dynamodb.DeleteItemInput{
		TableName: aws.String(r.TableName),
		Key: map[string]*dynamodb.AttributeValue{
			"hash": {S: aws.String(hash)},
		},
	})

	// Error while deleting record
	if err != nil {
		log.Print(err)
		return false, err
	}

	return true, nil
}
