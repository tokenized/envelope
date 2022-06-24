package base

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/tokenized/pkg/bitcoin"

	"github.com/pkg/errors"
)

var (
	// Known Protocol Identifiers
	ProtocolIDTokenized      = ProtocolID("TKN")
	ProtocolIDTokenizedTest  = ProtocolID("test.TKN")
	ProtocolIDFlag           = ProtocolID("flag")
	ProtocolIDUUID           = ProtocolID("uuid") // Protocol ID for Universally Unique IDentifiers
	ProtocolIDSignedMessages = ProtocolID("S")    // Protocol ID for Channels signed messages
	ProtocolIDInvoices       = ProtocolID("I")    // Protocol ID for Channels invoice negotiation
	ProtocolIDMerkleProof    = ProtocolID("MP")   // Protocol ID for Channels merkle proofs
	ProtocolIDReject         = ProtocolID("RJ")   // Protocol ID for Channels reject messages
	ProtocolIDMessageID      = ProtocolID("ID")   // Protocol ID for Channels message ids
	ProtocolIDRelationships  = ProtocolID("RS")   // Protocol ID for Channels relationship messages
	ProtocolIDResponse       = ProtocolID("RE")   // Protocol ID for Channels response messages

	ErrNotEnvelope     = errors.New("Not an envelope")
	ErrUnknownVersion  = errors.New("Unknown version")
	ErrInvalidEnvelope = errors.New("Invalid Envelope")
)

type ProtocolID bitcoin.Hex // Hex is just a byte slice that JSON marshals as hex
type ProtocolIDs []ProtocolID

type Data struct {
	ProtocolIDs ProtocolIDs
	Payload     bitcoin.ScriptItems
}

// ParseHeader parses an Envelope header and returns the version. Returns ErrNotEnvelope if it is
// not an Envelope.
func ParseHeader(buf *bytes.Reader) (uint8, error) {
	// Header
	if buf.Len() < 5 {
		return 0, ErrNotEnvelope
	}

	var b byte
	var err error

	b, err = buf.ReadByte()
	if err != nil {
		return 0, errors.Wrap(err, "read op return")
	}

	if b != bitcoin.OP_RETURN {
		if b != bitcoin.OP_FALSE {
			return 0, ErrNotEnvelope
		}

		b, err = buf.ReadByte()
		if err != nil {
			return 0, errors.Wrap(err, "read op return")
		}

		if b != bitcoin.OP_RETURN {
			return 0, ErrNotEnvelope
		}
	}

	// Envelope Protocol ID
	_, protocolID, err := bitcoin.ParsePushDataScript(buf)
	if err != nil {
		return 0, errors.Wrap(err, "parse protocol ID")
	}
	if len(protocolID) != 2 {
		return 0, ErrNotEnvelope
	}
	if protocolID[0] != 0xbd {
		return 0, ErrNotEnvelope
	}

	return protocolID[1], nil
}

func (id ProtocolID) String() string {
	if isText(id) {
		return string(id)
	}

	return fmt.Sprintf("0x%s", hex.EncodeToString(id))
}

// MarshalJSON converts to json.
func (id ProtocolID) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", id)), nil
}

// UnmarshalJSON converts from json.
func (id *ProtocolID) UnmarshalJSON(data []byte) error {
	l := len(data)
	if l < 2 {
		return errors.New("Missing quotes")
	}
	if data[0] != '"' || data[l-1] != '"' {
		return errors.New("Missing quotes")
	}

	s := string(data[1 : l-1])
	if strings.HasPrefix(s, "0x") {
		b, err := hex.DecodeString(s[2:])
		if err != nil {
			return errors.Wrap(err, "hex")
		}

		*id = ProtocolID(b)
		return nil
	}

	*id = ProtocolID(data[1 : l-1])
	return nil
}

// MarshalText returns the text encoding of the hash.
// Implements encoding.TextMarshaler interface.
func (id ProtocolID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText parses a text encoded hash and sets the value of this object.
// Implements encoding.TextUnmarshaler interface.
func (id *ProtocolID) UnmarshalText(text []byte) error {
	s := string(text)
	if strings.HasPrefix(s, "0x") {
		b, err := hex.DecodeString(s[2:])
		if err != nil {
			return errors.Wrap(err, "hex")
		}

		*id = ProtocolID(b)
		return nil
	}

	*id = ProtocolID(text)
	return nil
}

// MarshalBinary returns the binary encoding of the hash.
// Implements encoding.BinaryMarshaler interface.
func (id ProtocolID) MarshalBinary() ([]byte, error) {
	return id, nil
}

// UnmarshalBinary parses a binary encoded hash and sets the value of this object.
// Implements encoding.BinaryUnmarshaler interface.
func (id *ProtocolID) UnmarshalBinary(data []byte) error {
	*id = data
	return nil
}

func isText(bs []byte) bool {
	for _, b := range bs {
		if b < 0x20 { // ' ' space character
			return false
		}

		if b > 0x7e { // '~' tilde character
			return false
		}
	}

	return true
}
