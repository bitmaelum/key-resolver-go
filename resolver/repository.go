package resolver

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"os"
)

// ResolveInfoType returns information found in the resolver repository
type ResolveInfoType struct {
	Hash    string
	Routing string
	PubKey  string
	Pow     string
	Serial  int
}

// Repository to resolve records
type Repository interface {
	Get(hash string) (*ResolveInfoType, error)
	Create(hash, routing, publicKey, pow string) (bool, error)
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

	resolver = NewDynamoDBResolver(dynamodb.New(sess), os.Getenv("TABLE_NAME"))
	return resolver
}
