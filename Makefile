

BINARY_CLI=envelope

all: tools dep test dist

dep:
	go get ./...

tools:
	go get golang.org/x/lint/golint
	go get golang.org/x/tools/cmd/goimports

test:
	mkdir tmp || echo "directory tmp already exists"
	go test ./...

dist:
	mkdir dist || echo "directory dist already exists"
	go build -o dist/$(BINARY_CLI) cmd/$(BINARY_CLI)/main.go

format:
	goimports -w ./

protobuf:
	protoc -I internal/version_0/protobuf/ internal/version_0/protobuf/messages.proto --go_out=plugins=grpc:internal/version_0/protobuf
