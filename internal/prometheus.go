package internal

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

// LogMetric will log the given metric to the DynamoDB
func LogMetric(path string, statusCode int) {
	input := &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]*string{
			"#hits": aws.String("hits"),
		},
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":inc":  {N: aws.String("1")},
			":zero": {N: aws.String("0")},
		},
		TableName:        aws.String("prometheus"),
		UpdateExpression: aws.String("SET #hits = if_not_exists(#hits, :zero) + :inc"),
		Key: map[string]*dynamodb.AttributeValue{
			"path_code": {S: aws.String(path + " " + strconv.Itoa(statusCode))},
		},
	}

	dyna := getDyna()

	// Update logging
	_, _ = dyna.UpdateItem(input)
}

// ExportMetric will return a JSON output with the exported JSON log
func ExportMetric() *events.APIGatewayV2HTTPResponse {
	headers := map[string]string{}

	var body = ""
	body += "# HELP keyresolver_request BitMaelum keyresolver \n"
	body += "# TYPE keyresolver_request counter\n"

	input := &dynamodb.ScanInput{
	    ExpressionAttributeNames: map[string]*string{
	        "#path_code": aws.String("path_code"),
	        "#hits": aws.String("hits"),
	    },
	    ProjectionExpression: aws.String("#path_code, #hits"),
	    TableName:            aws.String("prometheus"),
	}

	dyna := getDyna()
	result, err := dyna.Scan(input)
	if err == nil {
		for i := range result.Items {

			s := result.Items[i]["path_code"].S
			parts := strings.Split(*s, " ")

			hits := result.Items[i]["hits"].N
			body += fmt.Sprintf("keyresolver_request{method=\"%s\", path=\"%s\", code=%s} = %s\n", parts[0], parts[1], parts[2], *hits)
		}
	}

	resp := &events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Headers:    headers,
		Body:       string(body),
	}

	return resp
}

func getDyna() *dynamodb.DynamoDB {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	return dynamodb.New(sess)
}
