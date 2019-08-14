package envelope

import (
	"bytes"

	"github.com/tokenized/envelope/pkg/golang/envelope/v0"
	"github.com/tokenized/smart-contract/pkg/bitcoin"

	"github.com/pkg/errors"
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

	var opReturn [2]byte
	_, err := buf.Read(opReturn[:])
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read op return")
	}

	if opReturn[0] != bitcoin.OP_FALSE || opReturn[1] != bitcoin.OP_RETURN {
		return nil, ErrNotEnvelope
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
