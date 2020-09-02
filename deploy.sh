#!/bin/sh

set -e

# Build
GOOS=linux go build -o main .

# Deploy to lambda
zip deployment.zip main
aws lambda --profile bitmaelum update-function-code --function-name key-resolve-staging --zip-file fileb://deployment.zip --region eu-west-1
aws lambda --profile bitmaelum update-function-code --function-name key-resolve-production --zip-file fileb://deployment.zip --region eu-west-1
