package v1

import (
	"bytes"

	"github.com/tokenized/pkg/bitcoin"

	"github.com/pkg/errors"
)

var (
	ErrNotEnvelope = errors.New("Not Envelope")

	ErrInvalidEnvelope = errors.New("Invalid Envelope")
)

// Serialize writes an OP_RETURN script in the "envelope" format containing the specified data.
func (m *Message) Serialize(buf *bytes.Buffer) error {
	// Header
	if err := buf.WriteByte(bitcoin.OP_FALSE); err != nil {
		return errors.Wrap(err, "op_false")
	}
	if err := buf.WriteByte(bitcoin.OP_RETURN); err != nil {
		return errors.Wrap(err, "op_return")
	}
	if err := bitcoin.WritePushDataScript(buf, []byte{0xbd, 0x01}); err != nil {
		return errors.Wrap(err, "envelope protocol id")
	}

	// Payload protocol IDs
	if _, err := buf.Write(bitcoin.PushNumberScript(int64(len(m.payloadProtocols)))); err != nil {
		return errors.Wrap(err, "payload protocol id count")
	}

	// Payload Protocol ID
	if len(m.payloadProtocols) == 0 {
		return errors.New("Payload protocol required")
	}
	for i, protocolID := range m.payloadProtocols {
		if err := bitcoin.WritePushDataScript(buf, protocolID); err != nil {
			return errors.Wrapf(err, "payload protocol id %d", i)
		}
	}

	// Number of payload push datas
	if _, err := buf.Write(bitcoin.PushNumberScript(int64(len(m.payloads)))); err != nil {
		return errors.Wrap(err, "payload count")
	}

	// Payloads
	for i, payload := range m.payloads {
		if err := bitcoin.WritePushDataScript(buf, payload); err != nil {
			return errors.Wrapf(err, "payload %d", i)
		}
	}

	return nil
}

// Deserialize reads the Message from an OP_RETURN script.
func Deserialize(buf *bytes.Reader) (*Message, error) {
	// Protocol IDs
	protocolIDCountItem, err := bitcoin.ParseScript(buf)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidEnvelope, errors.Wrap(err, "protocol ID count").Error())
	}

	protocolIDCount, err := bitcoin.ScriptNumberValue(protocolIDCountItem)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidEnvelope,
			errors.Wrap(err, "protocol ID count value").Error())
	}
	if protocolIDCount < 0 {
		return nil, errors.Wrapf(ErrInvalidEnvelope, "negative protocol id count %d",
			protocolIDCount)
	}

	result := &Message{}

	result.payloadProtocols = make([][]byte, protocolIDCount)
	for i := range result.payloadProtocols {
		protocolIDItem, err := bitcoin.ParseScript(buf)
		if err != nil {
			return nil, errors.Wrap(ErrInvalidEnvelope,
				errors.Wrapf(err, "protocol ID %d", i).Error())
		}

		switch protocolIDItem.Type {
		case bitcoin.ScriptItemTypeOpCode:
			result.payloadProtocols[i] = []byte{protocolIDItem.OpCode}

		case bitcoin.ScriptItemTypePushData:
			result.payloadProtocols[i] = protocolIDItem.Data

		default:
			return nil, errors.Wrap(ErrInvalidEnvelope, "unknown script item type")
		}
	}

	// Payloads
	payloadCountItem, err := bitcoin.ParseScript(buf)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidEnvelope, errors.Wrap(err, "payload count").Error())
	}

	payloadCount, err := bitcoin.ScriptNumberValue(payloadCountItem)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidEnvelope,
			errors.Wrap(err, "payload count value").Error())
	}
	if payloadCount < 0 {
		return nil, errors.Wrapf(ErrInvalidEnvelope, "negative payload count %d", payloadCount)
	}

	result.payloads = make([][]byte, payloadCount)
	for i := range result.payloads {
		payloadItem, err := bitcoin.ParseScript(buf)
		if err != nil {
			return nil, errors.Wrap(ErrInvalidEnvelope, errors.Wrapf(err, "payload %d", i).Error())
		}

		switch payloadItem.Type {
		case bitcoin.ScriptItemTypeOpCode:
			result.payloads[i] = []byte{payloadItem.OpCode}

		case bitcoin.ScriptItemTypePushData:
			result.payloads[i] = payloadItem.Data

		default:
			return nil, errors.Wrap(ErrInvalidEnvelope, "unknown script item type")
		}
	}

	return result, nil
}
