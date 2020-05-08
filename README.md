# Envelope System

This repository provides common encoding system for wrapping data in Bitcoin OP_RETURN scripts.

It provides a common system for identifying the payload data protocol, providing MetaNet hierarchy information, and encrypting some or all of the payload.
It supports 3 encryption scenarios through the use of Bitcoin private and public keys, input and output scripts, and Elliptic Curve Diffie Hellman for encryption key generation and sharing.
- Encrypting data privately.
- Encrypting data to be shared with one recipient.
- Encrypting data to be shared with multiple recipients.

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

The Protobuf message definitions are in [api/messages.proto](./api/messages.proto).

If the main payload is protobuf encoded, then the encrypted payloads can also contain protobuf encoded data. Then after the encrypted payloads are decrypted they can be appended to the main payload before decoding with protobuf. This allows selected fields to be encrypted.

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

The envelope system supports encrypting data using several key derivation methods. The encrypted data is contained in a list of `EncryptedPayload` fields in the "Envelope Data" `PUSH_OP`.

Each `EncryptedPayload` entry contains:
- `EncryptionType` - an integer currently 0 for direct and 1 for indirect.
- `Sender` - an index referencing the input of the sender.
- `Receivers` - a list of `Receiver` records containing information about the receiver.
- `Payload` - the actual encrypted data.

Each `Receiver` entry contains:
- `Index` - an index referencing the output of the receiver.
- `EncryptedKey` - the encrypted key if it is not the ECDH between the sender and receiver's keys.

### Integrated Encryption Scheme (IES)

Envelope uses its own integrated encryption scheme because it is designed to be embedded in a transaction on chain and linked to the keys and signatures of a transaction. Therefore it can be very simple as the actual encryption only has to worry about encrypting the data securely. Data integrity and authentication of sender and receiver are done with keys and signatures in the transaction.

256 bit (32 byte) keys are used and a `0xff` byte is appended to the plain text before encryption so any padding due to the 128 bit (16 byte) block size can be removed after decryption.

#### Encryption

- Append a `0xff` byte to the end of the unencrypted data (plain text)
- Encrypt using AES 256 bit keys with CBC (Cipher Block Chaining)
- Prepend the IV to the encrypted data (cipher text)

#### Decryption

- Extract IV from the beginning of the encrypted data (cipher text)
- Decrypt using AES 256 bit keys with CBC (Cipher Block Chaining)
- Truncate all bytes from the end of the unencrypted data up to and including the `0xff` added during encryption

### Direct Encryption

The `EncryptionType` field of encrypted payload is 0.  The `Sender` and `Receivers` fields are used to derive the encryption key.

Direct encryption is a method of encryption using an encryption key that can be derived from the public keys either in the transaction inputs and outputs or referenced by hashes in the inputs and outputs. The encryption key is derived using  and a private key for one of those public keys and at least one of those public keys

#### Private

The encryption key derived from sender's private key. Only the sender's private key can derive encryption key.

```
s = Sender's private key
e = Encryption key

e = SHA256(s)
```

#### Single Recipient

The encryption key is derived from sender and recipient keys. ECDH (Elliptic Curve Diffie Hellman) and one of those private keys and the other public key is used to derive the encryption key.

ECDH says that the sender's private key multiplied by the receiver's public key is equal to the sender's public key multiplied by the receiver's private key. Both parties can derive the same value with only their private key and the other's public key and no one else can without one of their private keys.

```
s = Sender's private key
S = Sender's public key
r = Receiver's private key
R = Receiver's public key
e = Encryption key

# ECDH defines the following equation
s * R = r * S

# We hash it for extra safety
e = SHA256(s * R) = SHA256(r * S)
```

There is an example implementation creating an on chain encrypted file [below](#private-file).

#### Multiple Recipients

The encryption key is random and encrypted within the message for each recipient. Any recipient with the sender's public key and their private key can derive an encryption key and use that to decrypt their encrypted copy of the message's encryption key.

### Indirect Encryption

The `EncryptionType` field of encrypted payload is 1. The `Sender` and `Receivers` fields are ignored.

Indirect encryption is a method of encryption using an encryption key that is negotiated beforehand. For example, an encryption key can be shared offline, or in a previous transaction.

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

### File System Example Usage

Envelope can be used to store files on chain. Keep in mind this is just an example. The exact specifics of a file storage protocol should be defined and shared before being used. We also recommend that when encrypting a file the file name and type be included in the encrypted payload instead of the Envelope header fields.

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

<a name="private-file"></a>
#### Private File

This shows a sample implementation to encrypt a PDF file in a bitcoin transaction. It uses "F" as the protocol identifier. This is just for example purposes and is not a defined protocol at this time. In this example the file name and mime type are put in the PayloadIdentifier and PayloadType header fields of the envelope and are therefore not encrypted. To include them in the encrypted data, the PayloadIdentifier and PayloadType fields can be left empty and a data format for the encrypted payload could be defined. It could include fields for filename, file type, and file data, as well as other fields deemed important. For example a private file protocol could be defined with the protocol identifier "P" and the payload would be a protobuf containing the fields "Name", "Type", and "Data".

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
tx := wire.NewMsgTx(1)

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

// Message will be encrypted with a secret that only those with senderPrivate/recipientPublic
//   or senderPublic/recipientPrivate will be able to derive.
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

# License

The Tokenized Envelope System is open-sourced software licensed under the [OPEN BITCOIN SV](LICENSE.md) license.
