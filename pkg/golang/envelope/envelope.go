package envelope

import (
	"bytes"

	v0 "github.com/tokenized/envelope/pkg/golang/envelope/v0"
	v1 "github.com/tokenized/envelope/pkg/golang/envelope/v1"
	"github.com/tokenized/pkg/bitcoin"

	"github.com/pkg/errors"
)

const (
	// Known Protocol Identifiers
	ProtocolIDTokenized     = "tokenized"
	ProtocolIDTokenizedTest = "test.tokenized"
	ProtocolIDFlag          = "flag"
	ProtocolIDUUID          = "uuid" // Protocol ID for Universally Unique IDentifiers
)

var (
	ErrNotEnvelope    = errors.New("Not an envelope")
	ErrUnknownVersion = errors.New("Unknown version")
)

type BaseMessage interface {
	EnvelopeVersion() uint8     // Envelope protocol version
	PayloadProtocols() [][]byte // Protocol IDs of payloads. (recommended to be ascii text)

	PayloadCount() int
	PayloadAt(offset int) []byte

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
		return nil, errors.Wrap(err, "read op return")
	}

	if b != bitcoin.OP_RETURN {
		if b != bitcoin.OP_FALSE {
			return nil, ErrNotEnvelope
		}

		b, err = buf.ReadByte()
		if err != nil {
			return nil, errors.Wrap(err, "read op return")
		}

		if b != bitcoin.OP_RETURN {
			return nil, ErrNotEnvelope
		}
	}

	// Envelope Protocol ID
	_, protocolID, err := bitcoin.ParsePushDataScript(buf)
	if err != nil {
		return nil, errors.Wrap(err, "parse protocol ID")
	}
	if len(protocolID) != 2 {
		return nil, ErrNotEnvelope
	}
	if protocolID[0] != 0xbd {
		return nil, ErrNotEnvelope
	}

	// Version 0 for backwards compatibility
	if protocolID[1] == 0 {
		result, err := v0.Deserialize(buf)
		if err == v0.ErrNotEnvelope {
			return nil, ErrNotEnvelope
		}
		return result, err
	}

	if protocolID[1] != 1 {
		return nil, ErrUnknownVersion
	}

	// Version 1
	result, err := v1.Deserialize(buf)
	if err == v1.ErrNotEnvelope {
		return nil, ErrNotEnvelope
	}
	return result, err
}
