# Envelope System

This repository provides common encoding system for wrapping data in Bitcoin OP_RETURN scripts.

It provides a common system for identifying the payload data protocol, providing MetaNet hierarchy information, and encrypting some or all of the payload.
It supports 3 encryption scenarios through the use of Bitcoin private and public keys, input and output scripts, and Elliptic Curve Diffie Hellman for encryption key generation and sharing.
- Encrypting data privately.
- Encrypting data to be shared with one recipient.
- Encrypting data to be shared with multiple recipients.

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

- `golang` - Go language implementation.

## Data Structure

The data is encoded as an unspendable OP_RETURN Bitcoin locking (output) script.

`OP_FALSE`
`OP_RETURN`
Ensure the output is provably unspendable.

`0x02 0xbd 0x00`
Push data containing 2 bytes. 0xbd is the envelope protocol ID and 0x00 is the envelope version.

`PUSH_OP Payload Protocol ID`
Push data containing the identifier of the payload's protocol.

`PUSH_OP Envelope Data`
Push data containing [protobuf](https://developers.google.com/protocol-buffers/) encoded data containing payload protocol version, content type, and content identifier as well as MetaNet and encrypted payloads.

If the main payload is protobuf encoded, then the encrypted payloads can also contain protobuf encoded data that can be appended to the payload before decoding with protobuf. This allows selected fields to be encrypted.

`PUSH_OP Payload`
The envelopes main payload.
