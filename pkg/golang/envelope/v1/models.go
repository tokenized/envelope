package v1

import "github.com/tokenized/envelope/pkg/golang/envelope/base"

const (
	version = uint8(1)
)

type Message struct {
	payloadProtocols base.ProtocolIDs
	payloads         [][]byte
}

// NewMessage creates a message.
func NewMessage(protocols base.ProtocolIDs, payloads [][]byte) *Message {
	return &Message{payloadProtocols: protocols, payloads: payloads}
}

func (m *Message) EnvelopeVersion() uint8 {
	return version
}

func (m *Message) PayloadProtocols() base.ProtocolIDs {
	return m.payloadProtocols
}

func (m *Message) PayloadCount() int {
	return len(m.payloads)
}

func (m *Message) PayloadAt(offset int) []byte {
	if offset >= len(m.payloads) {
		return nil
	}
	return m.payloads[offset]
}

func (m *Message) AddProtocolID(protocolID base.ProtocolID) {
	m.payloadProtocols = append(m.payloadProtocols, protocolID)
}

func (m *Message) AddPayload(payload []byte) {
	m.payloads = append(m.payloads, payload)
}
