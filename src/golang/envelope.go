package envelope

import (
	"bytes"
	"fmt"

	"github.com/tokenized/envelope/src/golang/internal/v0"
	"github.com/tokenized/envelope/src/golang/internal/v0/protobuf"
	"github.com/tokenized/smart-contract/pkg/bitcoin"
	"github.com/tokenized/smart-contract/pkg/wire"

	"github.com/pkg/errors"
)

type Message struct {
	envelopeVersion   uint8  // Envelope protocol version
	Protocol          []byte // Protocol ID of payload. (recommended to be ascii text)
	Version           uint64 // Protocol specific version for the payload.
	PayloadType       []byte // Data type of payload.
	Identifier        []byte // Protocol specific identifier for the payload. (i.e. message type, data name)
	metaNet           MetaNet
	encryptedPayloads []EncryptedPayload
	Payload           []byte
}

type MetaNet interface {
	Index() uint32
	PublicKey(tx *wire.MsgTx) (bitcoin.PublicKey, error)
	Parent() []byte
}

type EncryptedPayload interface {
	// SenderDecrypt decrypts the payload using the sender's private key and a receivers public key.
	// receiverKey can be nil when no receivers are included in the payload.
	SenderDecrypt(tx *wire.MsgTx, senderKey bitcoin.Key, receiverKey bitcoin.PublicKey) ([]byte, error)

	// ReceiverDecrypt decrypts the payload using the receiver's private key and the sender's public
	//   key from the tx input.
	ReceiverDecrypt(tx *wire.MsgTx, receiverKey bitcoin.Key) ([]byte, error)
}

// NewMessage creates a message.
func NewMessage(protocol []byte, version uint64, payload []byte) *Message {
	return &Message{
		envelopeVersion: envelopeVersion,
		Protocol:        protocol,
		Version:         version,
		Payload:         payload,
	}
}

func (m *Message) AddType(t []byte) {
	m.PayloadType = t
}

func (m *Message) AddIdentifier(i []byte) {
	m.Identifier = i
}

// AddMetaNet adds MetaNet data to the message.
// index is the input index that will contain the public key. Note, it will not contain the public
//   key when this function is called because it has not yet been signed. The public key will be in
//   the signature script after the input has been signed. The input must be P2PKH or P2RPH.
// If there is not parent then just use nil for parent.
func (m *Message) AddMetaNet(index uint32, publicKey bitcoin.PublicKey, parent []byte) {
	m.metaNet = v0.NewMetaNet(index, publicKey, parent)
}

func (m *Message) GetMetaNet() MetaNet {
	return m.metaNet
}

// NewEncryptedPayload creates an encrypted payload object.
// senderIndex is the input index containing the public key of the creator of the encrypted payload.
// sender is the key used to create the encrypted payload.
// receivers are the public keys of those receiving the encrypted payload.
// The data will be encrypted in different ways depending on the number of receivers.
//
// Sender:
//   Sender's input must be a P2PKH or a P2RPH unlocking script so that it contains the public key.
//
// Receivers:
//   Receiver's outputs must be P2PKH locking scripts so that it contains the hash of the public
//     key.
//   0 receivers - data is encrypted with sender's private key.
//   1 receiver  - data is encrypted with a derived shared secret.
//   2 receivers - data is encrypted with a random private key and the private key is encrypted
//     with the derived shared secret of each receiver and included in the message.
func (m *Message) AddEncryptedPayload(payload []byte, tx *wire.MsgTx, senderIndex uint32,
	sender bitcoin.Key, receivers []bitcoin.PublicKey) error {
	encryptedPayload, err := v0.NewEncryptedPayload(payload, tx, senderIndex, sender,
		receivers)
	if err != nil {
		return err
	}
	m.encryptedPayloads = append(m.encryptedPayloads, encryptedPayload)
	return nil
}

func (m *Message) GetEncryptedPayloads() []EncryptedPayload {
	return m.encryptedPayloads
}

var (
	ErrNotEnvelope = errors.New("Not an envelope")

	envelopeVersion = uint8(0) // Current Envelope Protocol Version
	baseHeader      = []byte{
		bitcoin.OP_FALSE,  // Unspendable
		bitcoin.OP_RETURN, // OP_RETURN
		2,                 // Push two bytes
		0xbd,              // Envelope Protocol ID
		envelopeVersion}   // Envelope Protocol Version
)

// Serialize creates an OP_RETURN script in the "envelope" format containing the specified data.
func (m *Message) Serialize(buf *bytes.Buffer) error {
	// Header OP_FALSE, OP_RETURN, Envelope Protocol, Protocol
	_, err := buf.Write(baseHeader)
	if err != nil {
		return errors.Wrap(err, "Failed to write header")
	}

	// Protocol
	if len(m.Protocol) == 0 {
		return errors.New("Protocol required")
	}
	err = bitcoin.WritePushDataScript(buf, m.Protocol)
	if err != nil {
		return errors.Wrap(err, "Failed to write protocol")
	}

	// Envelope
	envelope := protobuf.Envelope{
		Type:       m.PayloadType,
		Version:    m.Version,
		Identifier: m.Identifier,
	}

	// MetaNet
	var metaNet *v0.MetaNet
	if m.metaNet != nil {
		var ok bool
		metaNet, ok = m.metaNet.(*v0.MetaNet)
		if !ok {
			return errors.New("MetaNet is not current version")
		}
	}

	// Encrypted Payloads
	privatePayloads := make([]*v0.EncryptedPayload, 0, len(m.encryptedPayloads))
	for _, privatePayload := range m.encryptedPayloads {
		encryptedPayload, ok := privatePayload.(*v0.EncryptedPayload)
		if !ok {
			return errors.New("Not all encrypted payloads of current version")
		}
		privatePayloads = append(privatePayloads, encryptedPayload)
	}

	return v0.Serialize(buf, &envelope, metaNet, privatePayloads, m.Payload)
}

// Deserialize reads the Message from an OP_RETURN script.
func Deserialize(buf *bytes.Reader) (*Message, error) {
	// Header
	if buf.Len() < len(baseHeader) {
		return nil, ErrNotEnvelope
	}

	headerCheck := make([]byte, len(baseHeader)-1)
	_, err := buf.Read(headerCheck)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read script header")
	}

	if !bytes.Equal(baseHeader[:len(baseHeader)-1], headerCheck) {
		return nil, ErrNotEnvelope
	}

	// Envelope version
	envelopeVersion, err = buf.ReadByte()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read envelope version")
	}

	result := Message{envelopeVersion: uint8(envelopeVersion)}

	// Protocol ID
	var opCode byte
	opCode, result.Protocol, err = bitcoin.ParsePushDataScript(buf)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse protocol ID")
	}
	if len(result.Protocol) == 0 && opCode != bitcoin.OP_FALSE { // Non push data op code
		return nil, ErrNotEnvelope
	}

	switch result.envelopeVersion {
	case 0:
		var encryptedPayloads []*v0.EncryptedPayload
		result.Version, result.PayloadType, result.Identifier, result.metaNet, encryptedPayloads,
			result.Payload, err = v0.Deserialize(buf)
		if err != nil {
			return nil, err
		}
		result.encryptedPayloads = make([]EncryptedPayload, 0, len(encryptedPayloads))
		for _, encryptedPayload := range encryptedPayloads {
			result.encryptedPayloads = append(result.encryptedPayloads, encryptedPayload)
		}
		return &result, nil
	}

	return nil, fmt.Errorf("Unknown version : %d", result.envelopeVersion)
}
