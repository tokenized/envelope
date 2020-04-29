package v0

import (
	"github.com/tokenized/smart-contract/pkg/bitcoin"
	"github.com/tokenized/smart-contract/pkg/wire"
)

type Message struct {
	payloadProtocol   []byte // Protocol ID of payload. (recommended to be ascii text)
	payloadVersion    uint64 // Protocol specific version for the payload.
	payloadType       []byte // Data type of payload.
	payloadIdentifier []byte // Protocol specific identifier for the payload. (i.e. message type, data name)
	metaNet           *MetaNet
	encryptedPayloads []*EncryptedPayload
	payload           []byte
}

// EncryptedPayload holds encrypted data.
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
type EncryptedPayload struct {
	sender    uint32
	receivers []*Receiver
	payload   []byte // Data that is to be or was encrypted
}

// Index to receiver and if more than one, encrypted keys
type Receiver struct {
	index        uint32
	encryptedKey []byte
}

// NewMessage creates a message.
func NewMessage(protocol []byte, version uint64, payload []byte) *Message {
	return &Message{payloadProtocol: protocol, payloadVersion: version, payload: payload}
}

func (m *Message) EnvelopeVersion() uint8 {
	return 0
}

func (m *Message) PayloadProtocol() []byte {
	return m.payloadProtocol
}

func (m *Message) PayloadVersion() uint64 {
	return m.payloadVersion
}

func (m *Message) PayloadType() []byte {
	return m.payloadType
}

func (m *Message) PayloadIdentifier() []byte {
	return m.payloadIdentifier
}

func (m *Message) MetaNet() *MetaNet {
	return m.metaNet
}

func (m *Message) EncryptedPayloadCount() int {
	return len(m.encryptedPayloads)
}

func (m *Message) EncryptedPayload(i int) *EncryptedPayload {
	return m.encryptedPayloads[i]
}

func (m *Message) Payload() []byte {
	return m.payload
}

func (m *Message) SetPayloadType(t []byte) {
	m.payloadType = t
}

func (m *Message) SetPayloadIdentifier(i []byte) {
	m.payloadIdentifier = i
}

// AddMetaNet adds MetaNet data to the message.
// index is the input index that will contain the public key. Note, it will not contain the public
//   key when this function is called because it has not yet been signed. The public key will be in
//   the signature script after the input has been signed. The input must be P2PKH or P2RPH.
// If there is not parent then just use nil for parent.
func (m *Message) SetMetaNet(index uint32, publicKey bitcoin.PublicKey, parent []byte) {
	m.metaNet = NewMetaNet(index, publicKey, parent)
}

// AddEncryptedPayload creates an encrypted payload object and adds it to the message.
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
	encryptedPayload, err := NewEncryptedPayload(payload, tx, senderIndex, sender,
		receivers)
	if err != nil {
		return err
	}
	m.encryptedPayloads = append(m.encryptedPayloads, encryptedPayload)
	return nil
}

// AddEncryptedPayloadDirect creates an encrypted payload with all information necessary to decrypt,
//   except the private key, included in the message.
func (m *Message) AddEncryptedPayloadDirect(payload []byte, tx *wire.MsgTx, senderIndex uint32,
	sender bitcoin.Key, receivers []bitcoin.PublicKey) (bitcoin.Hash32, error) {
	encryptedPayload, key, err := NewEncryptedPayloadDirect(payload, tx, senderIndex, sender,
		receivers)
	if err != nil {
		return key, err
	}
	m.encryptedPayloads = append(m.encryptedPayloads, encryptedPayload)
	return key, nil
}

// AddEncryptedPayloadIndirect creates an encryped payload and adds it to the message. The message
//   is encrypted with the specified key instead of with keys in the message.
func (m *Message) AddEncryptedPayloadIndirect(payload []byte, tx *wire.MsgTx, key bitcoin.Hash32) error {
	encryptedPayload, err := NewEncryptedPayloadIndirect(payload, tx, key)
	if err != nil {
		return err
	}
	m.encryptedPayloads = append(m.encryptedPayloads, encryptedPayload)
	return nil
}
