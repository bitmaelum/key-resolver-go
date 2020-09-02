package resolver

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"log"
	"math/rand"
	"strconv"
)

type dynamoDbResolver struct {
	C         *dynamodb.DynamoDB
	TableName string
}

var errNotFound = errors.New("record not found")

// Record holds a DynamoDB record
type Record struct {
	Hash      string `dynamodbav:"hash"`
	Address   string `dynamodbav:"address"`
	PublicKey string `dynamodbav:"public_key"`
	Pow       string `dynamodbav:"proof"`
	Serial    int    `dynamodbav:"sn"`
}

// NewDynamoDBResolver returns a new resolver based on DynamoDB
func NewDynamoDBResolver(client *dynamodb.DynamoDB, tableName string) Repository {
	return &dynamoDbResolver{
		C:         client,
		TableName: tableName,
	}
}

func (r *dynamoDbResolver) Update(info *ResolveInfoType, server, publicKey string) (bool, error) {
	serial := strconv.Itoa(rand.Int())

	input := &dynamodb.UpdateItemInput{
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":s":   {S: aws.String(server)},
			":pk":  {S: aws.String(publicKey)},
			":sn":  {N: aws.String(serial)},
			":csn": {N: aws.String(strconv.Itoa(info.Serial))},
		},
		TableName:           aws.String(r.TableName),
		UpdateExpression:    aws.String("SET address=:s, public_key=:pk, sn=:sn"),
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

func (r *dynamoDbResolver) Create(hash, server, publicKey, pow string) (bool, error) {
	record := Record{
		Hash:      hash,
		Address:   server,
		PublicKey: publicKey,
		Pow:       pow,
		Serial:    rand.Int(),
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
		return nil, nil
	}

	record := Record{}
	err = dynamodbattribute.UnmarshalMap(result.Item, &record)
	if err != nil {
		log.Print(err)
		return nil, errNotFound
	}

	return &ResolveInfoType{
		Hash:   record.Hash,
		Server: record.Address,
		PubKey: record.PublicKey,
		Pow:    record.Pow,
		Serial: record.Serial,
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
