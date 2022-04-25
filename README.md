# Envelope System

This repository provides common encoding system for wrapping data in Bitcoin OP_RETURN scripts.

## Envelope v1

Envelope is designed to be as simple and light weight as possible. Envelope's main purpose is to identify and allow combining of encoding and data protocols within Bitcoin script. Multiple protocols can be specified, in order, to describe the order the protocols should be applied.

For example, an Envelope could specify a signing protocol and then a base data protocol. This would mean that the signing protocol should be applied first, which would likely involve parsing out the signature and checking it. Then the data protocol would be used to parse the data fields and apply meaning to them.

Envelope allows combining of independent protocols. This allows each protocol to be single purpose and as simple as possible. Attempting to combine signing, encryption, compression, and data protocols all in one is a mistake because then if just one falls short, or isn't accepted by the ecosystem, the entire protocol needs to be updated. If they are separate then each protocol can much more easily be updated or replaced by a better protocol. Plus developers can pick and choose the protocols that accomplish their goals most effectively without being locked into a specific set.

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

* `api` - Version 0 Protocol Buffer message definitions shared between languages.
* `pkg/golang` - Go language implementation.
* `pkg/typescript` - Incomplete Typescript language implementation.
* `pkg/...` - Add new language implementations.

## Data Structure

The data is encoded as an unspendable OP_RETURN Bitcoin locking (output) script.

`OP_FALSE OP_RETURN`

Ensures the output script is provably unspendable.

`0x02 0xbd 0x01`

Push data containing 2 bytes. 0xbd is the envelope protocol ID and 0x01 is the envelope version 1.

`PUSH_OP Payload Protocol ID Count`

Bitcoin script number specifying the number of push datas containing payload protocol IDs.

`PUSH_OP Payload Protocol IDs`

Specified number of push datas containing the protocol IDs that pertain to the payload.

`PUSH_OP Paylod Push Data Count`

Bitcoin script number specifying the number of push datas that make up the payload.

`PUSH_OP Payloads`

Specified number of push datas containing the payload.

### Tokenized Usage

The [Tokenized](https://tokenized.com) protocol uses envelope to wrap its messages.

* The envelope protocol IDs for a Tokenized action are "TKN" or "test.TKN".
* The paylod for a Tokenized action is made of 2 or 3 push datas.
* The first payload push data is a Bitcoin script number specifying the version, which is currently zero.
* The second payload push data contains the code specifying which type of Tokenized action is included.
* If the Tokenized action data is not empty, or "zero value", then the third push data containst the [protobuf](https://developers.google.com/protocol-buffers/) encoded data containing fields predefined for the Tokenized action code.

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

// Create Envelope Version 1 Message
message := v1.NewMessage([][]byte{"test.TKN"},
    [][]byte{bitcoin.PushNumberScript(int64(0)), []byte(contractOffer.Code())})

if len(payload) > 0 {
    // Only add action payload if it isn't empty.
    message.AddPayload(payload)
}

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

* The envelope payload protocolID is "F".
* The payload can contain 2 or 3 push datas.
* The first payload is the file name.
* The second payload is the MIME type of the file.
* If the file is not empty then the third paylod contains the file data. If the file is empty then only 2 payloads are specified for the envelope.


#### Public File
```
payload, err := ioutil.ReadFile("company_logo.png")
if err != nil {
    return errors.Wrap(err, "Failed to read file")
}

// Create Envelope Version 1 Message
message := v1.NewMessage([][]byte{"F"},
    [][]byte{[]byte("company_logo.png"), []byte("image/png")})

if len(payload) > 0 {
    // Only add action payload if it isn't empty.
    message.AddPayload(payload)
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
