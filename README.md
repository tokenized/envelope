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

* `api` - Protocol Buffer message definitions shared between languages.
* `pkg/golang` - Go language implementation.
* `pkg/typescript` - Incomplete Typescript language implementation.
* `pkg/...` - Add new language implementations.

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

## MetaNet

The envelope system supports MetaNet protocol by allowing you to specify that a public key in an input is the MetaNet node identifier. This ensures that the creator of the transaction has the associated private key and reduces data usage as a public key is usually required to post a transaction on chain anyway. You can also set the parent transaction ID. The data is protobuf encoded in the envelope data.

```
// Create version zero envelope message.
message := v0.NewMessage([]byte("test"), 0, payload)

// Set MetaNet data.
message.SetMetaNet(indexOfInputThatWillContainPublicKey, publicKey, parentTxId)
```

## Encryption

The envelope system supports encrypting data using several key derivation methods.

* Private - Encryption key is derived from sender's private key. Only sender's private key can derive encryption key.
* Single Recipient - Encryption key is derived from sender and recipient keys. One of those private keys and the other public key is required to derive the encryption key.
* Multiple Recipients - Encryption Key is random and encrypted within the message for each recipient. Any recipient with the sender's public key and their private key can derive an encryption key and use that to decrypt the message's encryption key.

## Usage

The `envelope` package provides a common interface to all versions of the protocol. Creating messages and the more advanced features, like MetaNet and Encryption, require directly using the version specific packages like `v0`.

### Sample Code
```
// Create Message
message := v0.NewMessage([]byte("tokenized"), 0, payload) // Tokenized version 0 payload

var buf bytes.Buffer
err := message.Serialize(&buf)
if err != nil {
    log.Fatalf("Failed Serialize : %s", err)
}

// Read Message
reader := bytes.NewReader(buf.Bytes())
readMessage, err := envelope.Deserialize(reader)
if err != nil {
	log.Fatalf("Failed Deserialize : %s", err)
}

if bytes.Equal(readMessage.PayloadProtocol(), []byte("tokenized"))  {
	// Process tokenized payload
}
```

### Tokenized Usage

The [Tokenized](https://tokenized.com) protocol uses envelope to wrap its messages.

* The envelope `PayloadProtocol` is "tokenized" or "test.tokenized".
* The envelope `PayloadIdentifier` specifies the action code of the message, or the message type.
* The envelope `Payload` is [protobuf](https://developers.google.com/protocol-buffers/) encoded data containing fields predefined for each message type.
* The envelope `EncryptedPayload` entries can be select fields [protobuf](https://developers.google.com/protocol-buffers/) encoded. Then after decryption they are just concatenated with the unencrypted payload and protobuf decoded.

```
contractOffer := actions.ContractOffer{
    ContractName: "Tokenized First Contract",
    BodyOfAgreementType: 2,
    BodyOfAgreement: ...,
    GoverningLaw: "AUD",
    VotingSystems: ...,
    ContractAuthFlags: ...,
    ...
}

// Protobuf Encode
payload, err := proto.Marshal(&contractOffer)
if err != nil {
	return errors.Wrap(err, "Failed to serialize action")
}

// Create Envelope Version Zero Message
message := v0.NewMessage("test.tokenized", Version, payload)
message.SetPayloadIdentifier([]byte("C1"))

// Convert Envelope Message to Bitcoin Output Script
var buf bytes.Buffer
err = message.Serialize(&buf)
if err != nil {
	return errors.Wrap(err, "Failed to serialize action envelope")
}
outputScript := buf.Bytes()

// Put output script in Bitcoin Tx Output as part of a Bitcoin transaction signed by the contract administrator, and addressed to the contract address.
tx.AddTxOut(wire.NewTxOut(0, outputScript))
```

### File System Usage

Envelope can be used to store files on chain.

* The envelope `PayloadProtocol` is "F".
* The envelope `PayloadIdentifier` specifies the name of the file.
* The envelope `PayloadType` specifies the MIME type of the file.
* The envelope `Payload` is the raw binary data of the file.
* An envelope `EncryptedPayload` entry can be used to store the encrypted raw binary file data. So that only the parties involved with the message, or those who know the secret, can see the file.


#### Public File
```
payload, err := ioutil.ReadFile("company_logo.png")
if err != nil {
    return errors.Wrap(err, "Failed to read file")
}

// Create Envelope Version Zero Message
message := v0.NewMessage("F", Version, payload)
message.SetPayloadIdentifier("company_logo.png")
message.SetPayloadType("image/png")

// Convert Envelope Message to Bitcoin Output Script
var buf bytes.Buffer
err = message.Serialize(&buf)
if err != nil {
	return errors.Wrap(err, "Failed to serialize envelope")
}
outputScript := buf.Bytes()

// Put output script in Bitcoin Tx Output.
tx.AddTxOut(wire.NewTxOut(0, outputScript))
```


#### Private File
```
privatePayload, err := ioutil.ReadFile("TermsOfSale.pdf")
if err != nil {
    return errors.Wrap(err, "Failed to read file")
}

// Create Envelope Version Zero Message
message := v0.NewMessage("F", Version, nil)
message.SetPayloadIdentifier("TermsOfSale.pdf")
message.SetPayloadType("application/pdf")

// Create Bitcoin transaction with sender and recipient.
tx := wire.NewMsgTx(2)

// Add input signed by sender.
senderKey := ...
sender := ...
tx.AddTxIn(sender)
senderIndex := 0

// Add output addressed to recipient, i.e. P2PKH.
recipientPublicKey := ...
recipient := ...
tx.AddTxOut(recipient)
recipientIndex := 0

// Message will be encrypted with a secret that only those with senderPrivate/recipientPublic or senderPublic/recipientPrivate will be able to derive.
err = message.AddEncryptedPayload(privatePayload, tx, senderIndex, senderKey,
    []bitcoin.PublicKey{recipientPublicKey})
if err != nil {
    return errors.Wrap(err, "Failed to add encrypted payload")
}

// Convert Envelope Message to Bitcoin Output Script
var buf bytes.Buffer
err = message.Serialize(&buf)
if err != nil {
	return errors.Wrap(err, "Failed to serialize envelope")
}
outputScript := buf.Bytes()

// Put output script in Bitcoin Tx Output.
tx.AddTxOut(wire.NewTxOut(0, outputScript))
```
