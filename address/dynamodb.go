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
)

type dynamoDbResolver struct {
	Dyna      dynamodbiface.DynamoDBAPI
	TableName string
}

// ErrNotFound will be returned when a record we are looking for is not found in the db
var ErrNotFound = errors.New("record not found")

// Record holds a DynamoDB record
type Record struct {
	Hash      string `dynamodbav:"hash"`
	Routing   string `dynamodbav:"routing"`
	PublicKey string `dynamodbav:"public_key"`
	Proof     string `dynamodbav:"proof"`
	Serial    uint64 `dynamodbav:"sn"`
}

// NewDynamoDBResolver returns a new resolver based on DynamoDB
func NewDynamoDBResolver(client dynamodbiface.DynamoDBAPI, tableName string) Repository {
	return &dynamoDbResolver{
		Dyna:      client,
		TableName: tableName,
	}
}

func (r *dynamoDbResolver) Update(info *ResolveInfoType, routing, publicKey string) (bool, error) {
	serial := strconv.FormatUint(uint64(time.Now().UnixNano()), 10)

	input := &dynamodb.UpdateItemInput{
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":s":   {S: aws.String(routing)},
			":pk":  {S: aws.String(publicKey)},
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

	_, err := r.Dyna.UpdateItem(input)
	if err != nil {
		log.Print(err)
		return false, err
	}

	return true, nil
}

func (r *dynamoDbResolver) Create(hash, routing, publicKey, proof string) (bool, error) {
	record := Record{
		Hash:      hash,
		Routing:   routing,
		PublicKey: publicKey,
		Proof:     proof,
		Serial:    uint64(timeNow().UnixNano()),
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

	record := Record{}
	err = dynamodbattribute.UnmarshalMap(result.Item, &record)
	if err != nil {
		log.Print(err)
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
