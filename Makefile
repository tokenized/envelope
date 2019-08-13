

BINARY_CLI=envelope

all: tools dep test dist

dep:
	go get ./...

tools:
	go get golang.org/x/lint/golint
	go get golang.org/x/tools/cmd/goimports

test:
	@mkdir tmp || echo "directory tmp already exists"
	go test ./...

dist:
	@mkdir dist || echo "directory dist already exists"
	go build -o dist/$(BINARY_CLI) cmd/$(BINARY_CLI)/main.go

format:
	goimports -w ./

protoc:
	protoc --proto_path=protobuf --go_out=plugins=grpc:src/golang/internal/v0/protobuf --js_out=library=protobuf,binary:src/typescript/v0 protobuf/messages.proto
