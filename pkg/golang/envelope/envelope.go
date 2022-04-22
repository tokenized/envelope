package envelope

import (
	"bytes"

	"github.com/tokenized/envelope/pkg/golang/envelope/base"
	v0 "github.com/tokenized/envelope/pkg/golang/envelope/v0"
	v1 "github.com/tokenized/envelope/pkg/golang/envelope/v1"
	"github.com/tokenized/pkg/bitcoin"

	"github.com/pkg/errors"
)

type BaseMessage interface {
	EnvelopeVersion() uint8             // Envelope protocol version
	PayloadProtocols() base.ProtocolIDs // Protocol IDs of payloads. (recommended to be ascii text)

	PayloadCount() int
	PayloadAt(offset int) []byte

	// Serialize creates an OP_RETURN script in the "envelope" format containing the specified data.
	Serialize(buf *bytes.Buffer) error
}

// Deserialize reads the Message from an OP_RETURN script.
func Deserialize(buf *bytes.Reader) (BaseMessage, error) {
	// Header
	if buf.Len() < 5 {
		return nil, base.ErrNotEnvelope
	}

	var b byte
	var err error

	b, err = buf.ReadByte()
	if err != nil {
		return nil, errors.Wrap(err, "read op return")
	}

	if b != bitcoin.OP_RETURN {
		if b != bitcoin.OP_FALSE {
			return nil, base.ErrNotEnvelope
		}

		b, err = buf.ReadByte()
		if err != nil {
			return nil, errors.Wrap(err, "read op return")
		}

		if b != bitcoin.OP_RETURN {
			return nil, base.ErrNotEnvelope
		}
	}

	// Envelope Protocol ID
	_, protocolID, err := bitcoin.ParsePushDataScript(buf)
	if err != nil {
		return nil, errors.Wrap(err, "parse protocol ID")
	}
	if len(protocolID) != 2 {
		return nil, base.ErrNotEnvelope
	}
	if protocolID[0] != 0xbd {
		return nil, base.ErrNotEnvelope
	}

	// Version 0 for backwards compatibility
	if protocolID[1] == 0 {
		return v0.Deserialize(buf)
	}

	if protocolID[1] != 1 {
		return nil, base.ErrUnknownVersion
	}

	// Version 1
	return v1.Deserialize(buf)
}
