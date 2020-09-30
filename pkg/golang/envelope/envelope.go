package envelope

import (
	"bytes"

	v0 "github.com/tokenized/envelope/pkg/golang/envelope/v0"
	"github.com/tokenized/pkg/bitcoin"

	"github.com/pkg/errors"
)

const (
	// Known Protocol Identifiers
	ProtocolIDTokenized     = "tokenized"
	ProtocolIDTokenizedTest = "test.tokenized"
	ProtocolIDFlag          = "flag"
	ProtocolIDUUID          = "uuid" // Protocol id for Universally Unique IDentifiers
)

var (
	ErrNotEnvelope    = errors.New("Not an envelope")
	ErrUnknownVersion = errors.New("Unknown version")
)

type BaseMessage interface {
	EnvelopeVersion() uint8    // Envelope protocol version
	PayloadProtocol() []byte   // Protocol ID of payload. (recommended to be ascii text)
	PayloadVersion() uint64    // Protocol specific version for the payload.
	PayloadType() []byte       // Data type of payload.
	PayloadIdentifier() []byte // Protocol specific identifier for the payload. (i.e. message type, data name)
	Payload() []byte

	SetPayloadType([]byte)

	SetPayloadIdentifier([]byte)

	// Serialize creates an OP_RETURN script in the "envelope" format containing the specified data.
	Serialize(buf *bytes.Buffer) error
}

// Deserialize reads the Message from an OP_RETURN script.
func Deserialize(buf *bytes.Reader) (BaseMessage, error) {
	// Header
	if buf.Len() < 5 {
		return nil, ErrNotEnvelope
	}

	var b byte
	var err error

	b, err = buf.ReadByte()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read op return")
	}

	if b != bitcoin.OP_RETURN {
		if b != bitcoin.OP_FALSE {
			return nil, ErrNotEnvelope
		}

		b, err = buf.ReadByte()
		if err != nil {
			return nil, errors.Wrap(err, "Failed to read op return")
		}

		if b != bitcoin.OP_RETURN {
			return nil, ErrNotEnvelope
		}
	}

	// Envelope Protocol ID
	_, protocolID, err := bitcoin.ParsePushDataScript(buf)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse protocol ID")
	}
	if len(protocolID) != 2 {
		return nil, ErrNotEnvelope
	}
	if protocolID[0] != 0xbd {
		return nil, ErrNotEnvelope
	}
	if protocolID[1] != 0 {
		return nil, ErrUnknownVersion
	}

	result, err := v0.Deserialize(buf)
	if err == v0.ErrNotEnvelope {
		return nil, ErrNotEnvelope
	}
	return result, err
}
