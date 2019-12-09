

all: tools dep test

dep:
	go get ./...

tools:
	go get golang.org/x/lint/golint
	go get golang.org/x/tools/cmd/goimports

test:
	@mkdir tmp || echo "tmp already exists"
	go test ./...

format:
	goimports -w ./

protoc:
	protoc --proto_path=api --go_out=plugins=grpc:pkg/golang/envelope/v0/protobuf --js_out=library=protobuf,binary:pkg/typescript/v0 api/messages.proto
