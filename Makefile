

all: tools dep test

dep:
	go get ./...

tools:
	go get golang.org/x/lint/golint
	go get golang.org/x/tools/cmd/goimports

test:
	go test ./...

format:
	goimports -w ./

protoc:
	protoc --proto_path=api --go_opt=paths=source_relative --go_out=pkg/golang/envelope/v0/protobuf --js_out=library=protobuf,binary:pkg/typescript/v0 api/envelope.proto --python_out=pkg/python
