package routing

import (
	"os"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

// ResolveInfoType returns information found in the resolver repository
type ResolveInfoType struct {
	Hash    string
	Routing string
	PubKey  string
	Serial  uint64
}

// Repository to resolve records
type Repository interface {
	Get(hash string) (*ResolveInfoType, error)
	Create(hash, routing, publicKey string) (bool, error)
	Update(info *ResolveInfoType, routing, publicKey string) (bool, error)
	Delete(hash string) (bool, error)
}

var resolver Repository

// GetResolveRepository returns a new repository based on DynamoDB
func GetResolveRepository() Repository {
	if resolver != nil {
		return resolver
	}

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	resolver = NewDynamoDBResolver(dynamodb.New(sess), os.Getenv("ROUTING_TABLE_NAME"))
	return resolver
}

// Sets the default repository for resolving. Can be used to override for mocking/testing purposes
func SetDefaultRepository(r Repository) {
	resolver = r
}
