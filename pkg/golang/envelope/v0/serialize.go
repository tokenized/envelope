package v0

import (
	"bytes"

	"github.com/tokenized/envelope/pkg/golang/envelope/v0/protobuf"
	"github.com/tokenized/smart-contract/pkg/bitcoin"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
)

var (
	ErrNotEnvelope = errors.New("Not an envelope")
)

// Serialize writes an OP_RETURN script in the "envelope" format containing the specified data.
func (m *Message) Serialize(buf *bytes.Buffer) error {
	// Header
	if err := buf.WriteByte(bitcoin.OP_FALSE); err != nil {
		return errors.Wrap(err, "Failed to write header")
	}
	if err := buf.WriteByte(bitcoin.OP_RETURN); err != nil {
		return errors.Wrap(err, "Failed to write header")
	}
	if err := bitcoin.WritePushDataScript(buf, []byte{0xbd, 0x00}); err != nil {
		return errors.Wrap(err, "Failed to write envelope protocol ID")
	}

	// Protocol
	if len(m.payloadProtocol) == 0 {
		return errors.New("Payload protocol required")
	}
	if err := bitcoin.WritePushDataScript(buf, m.payloadProtocol); err != nil {
		return errors.Wrap(err, "Failed to write payload protocol")
	}

	// Envelope
	envelope := protobuf.Envelope{
		Version:    m.payloadVersion,
		Type:       m.payloadType,
		Identifier: m.payloadIdentifier,
	}

	// Metanet
	// Convert to protobuf
	if m.metaNet != nil {
		envelope.MetaNet = &protobuf.MetaNet{
			Index:  m.metaNet.index,
			Parent: m.metaNet.parent,
		}
	}

	// Encrypted payloads
	// Convert to protobuf
	envelope.EncryptedPayloads = make([]*protobuf.EncryptedPayload, 0, len(m.encryptedPayloads))
	for _, encryptedPayload := range m.encryptedPayloads {
		pbEncryptedPayload := protobuf.EncryptedPayload{
			Sender:         encryptedPayload.sender,
			EncryptionType: encryptedPayload.encryptionType,
		}

		// Receivers
		pbEncryptedPayload.Receivers = make([]*protobuf.Receiver, 0, len(encryptedPayload.receivers))
		for _, receiver := range encryptedPayload.receivers {
			pbEncryptedPayload.Receivers = append(pbEncryptedPayload.Receivers, &protobuf.Receiver{
				Index:        receiver.index,
				EncryptedKey: receiver.encryptedKey,
			})
		}

		// Payload
		pbEncryptedPayload.Payload = encryptedPayload.payload

		envelope.EncryptedPayloads = append(envelope.EncryptedPayloads, &pbEncryptedPayload)
	}

	// Serialize envelope
	data, err := proto.Marshal(&envelope)
	if err != nil {
		return errors.Wrap(err, "Failed to serialize envelope")
	}

	if err := bitcoin.WritePushDataScript(buf, data); err != nil {
		return errors.Wrap(err, "Failed to write envelope")
	}

	// Public payload
	if err := bitcoin.WritePushDataScript(buf, m.payload); err != nil {
		return errors.Wrap(err, "Failed to write payload push")
	}

	return nil
}

// Deserialize reads the Message from an OP_RETURN script.
func Deserialize(buf *bytes.Reader) (*Message, error) {
	var result Message

	// Protocol ID
	var opCode byte
	var err error
	opCode, result.payloadProtocol, err = bitcoin.ParsePushDataScript(buf)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse protocol ID")
	}
	if len(result.payloadProtocol) == 0 && opCode != bitcoin.OP_FALSE { // Non push data op code
		return nil, ErrNotEnvelope
	}

	// Envelope
	_, envelopeData, err := bitcoin.ParsePushDataScript(buf)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read MetaNet data")
	}

	var envelope protobuf.Envelope
	if len(envelopeData) != 0 {
		if err = proto.Unmarshal(envelopeData, &envelope); err != nil {
			return nil, errors.Wrap(err, "Failed envelope protobuf unmarshaling")
		}
	}

	result.payloadVersion = envelope.GetVersion()
	result.payloadType = envelope.GetType()
	result.payloadIdentifier = envelope.GetIdentifier()

	// MetaNet
	pbMetaNet := envelope.GetMetaNet()
	if pbMetaNet != nil {
		result.metaNet = &MetaNet{
			index:  pbMetaNet.GetIndex(),
			parent: pbMetaNet.GetParent(),
		}
	}

	// Encrypted payloads
	pbEncryptedPayloads := envelope.GetEncryptedPayloads()
	result.encryptedPayloads = make([]*EncryptedPayload, 0, len(pbEncryptedPayloads))
	for _, pbEncryptedPayload := range pbEncryptedPayloads {
		encryptedPayload := EncryptedPayload{
			encryptionType: pbEncryptedPayload.EncryptionType,
		}

		// Sender
		encryptedPayload.sender = pbEncryptedPayload.GetSender()

		// Receivers
		pbReceivers := pbEncryptedPayload.GetReceivers()
		encryptedPayload.receivers = make([]*Receiver, 0, len(pbReceivers))
		for _, pbReceiver := range pbReceivers {
			encryptedPayload.receivers = append(encryptedPayload.receivers, &Receiver{
				index:        pbReceiver.GetIndex(),
				encryptedKey: pbReceiver.GetEncryptedKey(),
			})
		}

		// Payload
		encryptedPayload.payload = pbEncryptedPayload.GetPayload()

		result.encryptedPayloads = append(result.encryptedPayloads, &encryptedPayload)
	}

	// Public payload
	_, result.payload, err = bitcoin.ParsePushDataScript(buf)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read payload")
	}

	return &result, nil
}
