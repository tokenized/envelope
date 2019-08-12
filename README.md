# Envelope System

This repository provides common encoding and functions for wrapping data in Bitcoin OP_RETURN scripts.

It provides a common system for identifying the protocol of the contained data as well as encryption and providing a data hierarchy through MetaNet.

### License

Copyright 2019 Tokenized Group Pty Ltd.

## Getting Started

#### First, clone the GitHub repo.
```
# Create parent directory
mkdir -p $GOPATH/src/github.com/tokenized
# Go into parent directory
cd $GOPATH/src/github.com/tokenized
# Clone repository
git clone https://github.com/tokenized/envelope.git
```

#### Navigate to the root directory and run `make`.
```
# Go into repository directory
cd envelope
# Build project
make
```

## Project Structure

- `cmd/envelope` - Command line interface
- `internal` - Internal versioning system
- `envelope.go` - Serialize and encryption functions

## Usage
