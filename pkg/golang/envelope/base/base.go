package base

import (
	"errors"

	"github.com/tokenized/pkg/bitcoin"
)

var (
	// Known Protocol Identifiers
	ProtocolIDTokenized      = ProtocolID("TKN")
	ProtocolIDTokenizedTest  = ProtocolID("test.TKN")
	ProtocolIDFlag           = ProtocolID("flag")
	ProtocolIDUUID           = ProtocolID("uuid") // Protocol ID for Universally Unique IDentifiers
	ProtocolIDSignedMessages = ProtocolID("S")    // Protocol ID for signed messages
	ProtocolIDInvoices       = ProtocolID("I")    // Protocol ID for invoice negot

	ErrNotEnvelope     = errors.New("Not an envelope")
	ErrUnknownVersion  = errors.New("Unknown version")
	ErrInvalidEnvelope = errors.New("Invalid Envelope")
)

type ProtocolID bitcoin.Hex
type ProtocolIDs []ProtocolID // hex is just byte slice that JSON marshals as hex

type Data struct {
	ProtocolIDs ProtocolIDs
	Payload     bitcoin.ScriptItems
}
