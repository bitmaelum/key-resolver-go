#!/bin/sh

GOPATH=$(go env GOPATH)

go get -u golang.org/x/lint/golint
go get -u github.com/gordonklaus/ineffassign
go get -u github.com/fzipp/gocyclo

echo "Check format"
gofmt -l .

echo "Check vet"
go vet ./...

echo "Check lint"
"$GOPATH"/bin/golint ./...

echo "Check ineffassign"
"$GOPATH"/bin/ineffassign ./*

echo "Check gocyclo"
"$GOPATH"/bin/gocyclo -over 15 .

echo "Check unit tests"
go test ./...
