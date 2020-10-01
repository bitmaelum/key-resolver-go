package organisation

import (
	"os"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

// ResolveInfoType returns information found in the resolver repository
type ResolveInfoType struct {
<<<<<<< HEAD
	Hash   string
	PubKey string
	Proof  string
	Serial uint64
=======
	Hash        string
	PubKey      string
	Proof       string
	Validations []string
	Serial      int
>>>>>>> bitmaelum/develop
}

// Repository to resolve records
type Repository interface {
	Get(hash string) (*ResolveInfoType, error)
	Create(hash, publicKey, proof string, validations []string) (bool, error)
	Update(info *ResolveInfoType, publicKey, proof string, validations []string) (bool, error)
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

	resolver = NewDynamoDBResolver(dynamodb.New(sess), os.Getenv("ORGANISATION_TABLE_NAME"))
	return resolver
}
