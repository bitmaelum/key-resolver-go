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
	"errors"
	"log"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
)

type dynamoDbResolver struct {
	Dyna             dynamodbiface.DynamoDBAPI
	TableName        string
	HistoryTableName string
}

// Error codes
var (
	ErrNotFound     = errors.New("record not found")
	ErrCannotUpdate = errors.New("cannot update record")
)

// record holds a DynamoDB record
type recordType struct {
	Hash      string `dynamodbav:"hash"`
	Routing   string `dynamodbav:"routing"`
	PublicKey string `dynamodbav:"public_key"`
	Proof     string `dynamodbav:"proof"`
	Serial    uint64 `dynamodbav:"sn"`
	Deleted   bool   `dynamodbav:"deleted"`
	DeletedAt uint64 `dynamodbav:"deleted_at"`
}

type historyRecordType struct {
	Hash        string    `dynamodbav:"hash"`
	Fingerprint string    `dynamodbav:"fingerprint"`
	Status      KeyStatus `dynamodbav:"status"`
}

// NewDynamoDBResolver returns a new resolver based on DynamoDB
func NewDynamoDBResolver(client dynamodbiface.DynamoDBAPI, tableName, historyTableName string) Repository {
	return &dynamoDbResolver{
		Dyna:             client,
		TableName:        tableName,
		HistoryTableName: historyTableName,
	}
}

func (r *dynamoDbResolver) Update(info *ResolveInfoType, routing string, publicKey *bmcrypto.PubKey) (bool, error) {
	serial := strconv.FormatUint(uint64(time.Now().UnixNano()), 10)

	input := &dynamodb.UpdateItemInput{
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":s":   {S: aws.String(routing)},
			":pk":  {S: aws.String(publicKey.String())},
			":sn":  {N: aws.String(serial)},
			":csn": {N: aws.String(strconv.FormatUint(info.Serial, 10))},
		},
		TableName:           aws.String(r.TableName),
		UpdateExpression:    aws.String("SET routing=:s, public_key=:pk, sn=:sn"),
		ConditionExpression: aws.String("sn = :csn"),
		Key: map[string]*dynamodb.AttributeValue{
			"hash": {S: aws.String(info.Hash)},
		},
	}

	// Update key history
	_, err := r.updateKeyHistory(info.Hash, publicKey.Fingerprint(), KSNormal)
	if err != nil {
		return false, err
	}

	// Update address record
	_, err = r.Dyna.UpdateItem(input)
	if err != nil {
		log.Print(err)
		return false, err
	}

	return true, nil
}

func (r *dynamoDbResolver) Create(hash, routing string, publicKey *bmcrypto.PubKey, proof string) (bool, error) {
	record := recordType{
		Hash:      hash,
		Routing:   routing,
		PublicKey: publicKey.String(),
		Proof:     proof,
		Serial:    uint64(TimeNow().UnixNano()),
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

	// Update key history
	_, err = r.updateKeyHistory(hash, publicKey.Fingerprint(), KSNormal)
	if err != nil {
		return false, err
	}

	// Create address record
	_, err = r.Dyna.PutItem(input)
	return err == nil, err
}

func (r *dynamoDbResolver) Get(hash string) (*ResolveInfoType, error) {
	result, err := r.Dyna.GetItem(&dynamodb.GetItemInput{
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

	record := recordType{}
	err = dynamodbattribute.UnmarshalMap(result.Item, &record)
	if err != nil {
		log.Print(err)
		return nil, ErrNotFound
	}

	// We would prefer if we didn't retrieve it from the Getitem input
	if record.Deleted {
		return nil, ErrNotFound
	}

	return &ResolveInfoType{
		Hash:      record.Hash,
		RoutingID: record.Routing,
		PubKey:    record.PublicKey,
		Proof:     record.Proof,
		Serial:    record.Serial,
	}, nil
}

func (r *dynamoDbResolver) Delete(hash string) (bool, error) {
	_, err := r.Dyna.DeleteItem(&dynamodb.DeleteItemInput{
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

func (r *dynamoDbResolver) SoftDelete(hash string) (bool, error) {
	input := &dynamodb.UpdateItemInput{
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":dt": {N: aws.String(strconv.FormatInt(time.Now().Unix(), 10))},
		},
		TableName:        aws.String(r.TableName),
		UpdateExpression: aws.String("SET deleted=1, deleted_at=:dt"),
		Key: map[string]*dynamodb.AttributeValue{
			"hash": {S: aws.String(hash)},
		},
	}

	_, err := r.Dyna.UpdateItem(input)
	if err != nil {
		log.Print(err)
		return false, err
	}

	return true, nil
}

func (r *dynamoDbResolver) SoftUndelete(hash string) (bool, error) {
	input := &dynamodb.UpdateItemInput{
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":dt": {N: aws.String("")},
		},
		TableName:        aws.String(r.TableName),
		UpdateExpression: aws.String("SET deleted=0, deleted_at=:dt"),
		Key: map[string]*dynamodb.AttributeValue{
			"hash": {S: aws.String(hash)},
		},
	}

	_, err := r.Dyna.UpdateItem(input)
	if err != nil {
		log.Print(err)
		return false, err
	}

	return true, nil
}

func (r *dynamoDbResolver) GetKeyStatus(hash string, fingerprint string) (KeyStatus, error) {
	result, err := r.Dyna.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(r.HistoryTableName),
		Key: map[string]*dynamodb.AttributeValue{
			"hash":        {S: aws.String(hash)},
			"fingerprint": {S: aws.String(fingerprint)},
		},
	})
	// Error while fetching record
	if err != nil {
		return KSNormal, err
	}

	// Item not found
	if result.Item == nil {
		return KSNormal, ErrNotFound
	}

	record := historyRecordType{}
	err = dynamodbattribute.UnmarshalMap(result.Item, &record)
	if err != nil {
		log.Print(err)
		return KSNormal, ErrNotFound
	}

	return record.Status, nil
}

func (r *dynamoDbResolver) SetKeyStatus(hash string, fingerprint string, status KeyStatus) error {
	// Make sure key exists before updating
	_, err := r.GetKeyStatus(hash, fingerprint)
	if err != nil {
		return err
	}

	ok, err := r.updateKeyHistory(hash, fingerprint, status)
	if err != nil {
		return err
	}

	if !ok {
		return ErrCannotUpdate
	}

	return nil
}

func (r *dynamoDbResolver) updateKeyHistory(hash, fingerprint string, status KeyStatus) (bool, error) {
	av, err := dynamodbattribute.MarshalMap(historyRecordType{
		Hash:        hash,
		Fingerprint: fingerprint,
		Status:      status,
	})
	if err != nil {
		return false, err
	}

	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(r.HistoryTableName),
	}

	_, err = r.Dyna.PutItem(input)
	return err == nil, err
}
