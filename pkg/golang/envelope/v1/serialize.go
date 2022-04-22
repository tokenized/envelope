package v1

import (
	"bytes"

	"github.com/tokenized/envelope/pkg/golang/envelope/base"
	"github.com/tokenized/pkg/bitcoin"

	"github.com/pkg/errors"
)

func Wrap(protocolIDs base.ProtocolIDs, payload bitcoin.ScriptItems) bitcoin.ScriptItems {
	scriptItems := HeaderScriptItems(protocolIDs)

	// Number of payload push datas
	scriptItems = append(scriptItems, bitcoin.PushNumberScriptItem(int64(len(payload))))

	return append(scriptItems, payload...)
}

func HeaderScriptItems(protocolIDs base.ProtocolIDs) bitcoin.ScriptItems {
	// OP_FALSE, OP_RETURN
	result := bitcoin.ScriptItems{bitcoin.NewOpCodeScriptItem(bitcoin.OP_FALSE)}
	result = append(result, bitcoin.NewOpCodeScriptItem(bitcoin.OP_RETURN))

	// Envelope Version 1 Protocol ID
	result = append(result, bitcoin.NewPushDataScriptItem([]byte{0xbd, 0x01}))

	// Protocol IDs
	result = append(result, bitcoin.PushNumberScriptItem(int64(len(protocolIDs))))
	for _, protocolID := range protocolIDs {
		result = append(result, bitcoin.NewPushDataScriptItem(protocolID))
	}

	return result
}

func WriteHeader(buf *bytes.Buffer, protocolIDs base.ProtocolIDs) error {
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
	if _, err := buf.Write(bitcoin.PushNumberScript(int64(len(protocolIDs)))); err != nil {
		return errors.Wrap(err, "payload protocol id count")
	}

	// Payload Protocol ID
	if len(protocolIDs) == 0 {
		return errors.New("Payload protocol required")
	}
	for i, protocolID := range protocolIDs {
		if err := bitcoin.WritePushDataScript(buf, protocolID); err != nil {
			return errors.Wrapf(err, "payload protocol id %d", i)
		}
	}

	return nil
}

func Parse(buf *bytes.Reader) (base.ProtocolIDs, bitcoin.ScriptItems, error) {
	protocolIDs, err := ParseProtocolIDs(buf)
	if err != nil {
		return nil, nil, errors.Wrap(err, "protocol ids")
	}

	// Payloads
	payloadCountItem, err := bitcoin.ParseScript(buf)
	if err != nil {
		return nil, nil, errors.Wrap(base.ErrInvalidEnvelope,
			errors.Wrap(err, "payload count").Error())
	}

	payloadCount, err := bitcoin.ScriptNumberValue(payloadCountItem)
	if err != nil {
		return nil, nil, errors.Wrap(base.ErrInvalidEnvelope,
			errors.Wrap(err, "payload count value").Error())
	}
	if payloadCount < 0 {
		return nil, nil, errors.Wrapf(base.ErrInvalidEnvelope, "negative payload count %d",
			payloadCount)
	}

	payload, err := bitcoin.ParseScriptItems(buf, int(payloadCount))
	if err != nil {
		return nil, nil, errors.Wrap(err, "payload")
	}

	return protocolIDs, payload, nil
}

func ParseHeader(buf *bytes.Reader) error {
	// Header
	if buf.Len() < 5 {
		return base.ErrNotEnvelope
	}

	var b byte
	var err error

	b, err = buf.ReadByte()
	if err != nil {
		return errors.Wrap(err, "read op return")
	}

	if b != bitcoin.OP_RETURN {
		if b != bitcoin.OP_FALSE {
			return base.ErrNotEnvelope
		}

		b, err = buf.ReadByte()
		if err != nil {
			return errors.Wrap(err, "read op return")
		}

		if b != bitcoin.OP_RETURN {
			return base.ErrNotEnvelope
		}
	}

	// Envelope Protocol ID
	_, protocolID, err := bitcoin.ParsePushDataScript(buf)
	if err != nil {
		return errors.Wrap(err, "parse protocol ID")
	}
	if len(protocolID) != 2 {
		return base.ErrNotEnvelope
	}
	if protocolID[0] != 0xbd {
		return base.ErrNotEnvelope
	}

	if protocolID[1] != 1 {
		return base.ErrUnknownVersion
	}

	return nil
}

func ParseProtocolIDs(buf *bytes.Reader) (base.ProtocolIDs, error) {
	if err := ParseHeader(buf); err != nil {
		return nil, errors.Wrap(err, "header")
	}

	// Protocol ID Count
	protocolIDCountItem, err := bitcoin.ParseScript(buf)
	if err != nil {
		return nil, errors.Wrap(base.ErrInvalidEnvelope,
			errors.Wrap(err, "protocol ID count").Error())
	}

	protocolIDCount, err := bitcoin.ScriptNumberValue(protocolIDCountItem)
	if err != nil {
		return nil, errors.Wrap(base.ErrInvalidEnvelope,
			errors.Wrap(err, "protocol ID count value").Error())
	}
	if protocolIDCount < 0 {
		return nil, errors.Wrapf(base.ErrInvalidEnvelope, "negative protocol id count %d",
			protocolIDCount)
	}

	// Protocol IDs
	protocolIDs := make(base.ProtocolIDs, protocolIDCount)
	for i := range protocolIDs {
		protocolIDItem, err := bitcoin.ParseScript(buf)
		if err != nil {
			return nil, errors.Wrap(base.ErrInvalidEnvelope,
				errors.Wrapf(err, "protocol ID %d", i).Error())
		}

		switch protocolIDItem.Type {
		case bitcoin.ScriptItemTypeOpCode:
			protocolIDs[i] = base.ProtocolID{protocolIDItem.OpCode}

		case bitcoin.ScriptItemTypePushData:
			protocolIDs[i] = base.ProtocolID(protocolIDItem.Data)

		default:
			return nil, errors.Wrap(base.ErrInvalidEnvelope, "unknown script item type")
		}
	}

	return protocolIDs, nil
}

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
		return nil, errors.Wrap(base.ErrInvalidEnvelope,
			errors.Wrap(err, "protocol ID count").Error())
	}

	protocolIDCount, err := bitcoin.ScriptNumberValue(protocolIDCountItem)
	if err != nil {
		return nil, errors.Wrap(base.ErrInvalidEnvelope,
			errors.Wrap(err, "protocol ID count value").Error())
	}
	if protocolIDCount < 0 {
		return nil, errors.Wrapf(base.ErrInvalidEnvelope, "negative protocol id count %d",
			protocolIDCount)
	}

	result := &Message{}

	result.payloadProtocols = make(base.ProtocolIDs, protocolIDCount)
	for i := range result.payloadProtocols {
		protocolIDItem, err := bitcoin.ParseScript(buf)
		if err != nil {
			return nil, errors.Wrap(base.ErrInvalidEnvelope,
				errors.Wrapf(err, "protocol ID %d", i).Error())
		}

		switch protocolIDItem.Type {
		case bitcoin.ScriptItemTypeOpCode:
			result.payloadProtocols[i] = base.ProtocolID{protocolIDItem.OpCode}

		case bitcoin.ScriptItemTypePushData:
			result.payloadProtocols[i] = base.ProtocolID(protocolIDItem.Data)

		default:
			return nil, errors.Wrap(base.ErrInvalidEnvelope, "unknown script item type")
		}
	}

	// Payloads
	payloadCountItem, err := bitcoin.ParseScript(buf)
	if err != nil {
		return nil, errors.Wrap(base.ErrInvalidEnvelope, errors.Wrap(err, "payload count").Error())
	}

	payloadCount, err := bitcoin.ScriptNumberValue(payloadCountItem)
	if err != nil {
		return nil, errors.Wrap(base.ErrInvalidEnvelope,
			errors.Wrap(err, "payload count value").Error())
	}
	if payloadCount < 0 {
		return nil, errors.Wrapf(base.ErrInvalidEnvelope, "negative payload count %d", payloadCount)
	}

	result.payloads = make([][]byte, payloadCount)
	for i := range result.payloads {
		payloadItem, err := bitcoin.ParseScript(buf)
		if err != nil {
			return nil, errors.Wrap(base.ErrInvalidEnvelope,
				errors.Wrapf(err, "payload %d", i).Error())
		}

		switch payloadItem.Type {
		case bitcoin.ScriptItemTypeOpCode:
			result.payloads[i] = []byte{payloadItem.OpCode}

		case bitcoin.ScriptItemTypePushData:
			result.payloads[i] = payloadItem.Data

		default:
			return nil, errors.Wrap(base.ErrInvalidEnvelope, "unknown script item type")
		}
	}

	return result, nil
}
