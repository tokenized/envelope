package v0

import (
	"bytes"

	"github.com/tokenized/envelope/src/golang/internal/v0/protobuf"
	"github.com/tokenized/smart-contract/pkg/bitcoin"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
)

// Serialize writes an OP_RETURN script in the "envelope" format containing the specified data.
func Serialize(buf *bytes.Buffer, env *protobuf.Envelope, mn *MetaNet,
	privatePayloads []*EncryptedPayload, payload []byte) error {

	// Metanet
	// Convert to protobuf
	if mn != nil {
		env.MetaNet = &protobuf.MetaNet{
			Index:  mn.index,
			Parent: mn.parent,
		}
	}

	// Encrypted payloads
	// Convert to protobuf
	env.EncryptedPayloads = make([]*protobuf.EncryptedPayload, 0, len(privatePayloads))
	for _, privatePayload := range privatePayloads {
		var data protobuf.EncryptedPayload

		// Sender
		data.Sender = privatePayload.sender

		// Receivers
		data.Receivers = make([]*protobuf.Receiver, 0, len(privatePayload.receivers))
		for _, receiver := range privatePayload.receivers {
			data.Receivers = append(data.Receivers, &protobuf.Receiver{
				Index:        receiver.index,
				EncryptedKey: receiver.encryptedKey,
			})
		}

		// Payload
		data.Payload = privatePayload.payload

		env.EncryptedPayloads = append(env.EncryptedPayloads, &data)
	}

	// Serialize envelope
	data, err := proto.Marshal(env)
	if err != nil {
		return errors.Wrap(err, "Failed to serialize envelope")
	}

	err = bitcoin.WritePushDataScript(buf, data)
	if err != nil {
		return errors.Wrap(err, "Failed to write envelope")
	}

	// Public payload
	err = bitcoin.WritePushDataScript(buf, payload)
	if err != nil {
		return errors.Wrap(err, "Failed to write payload push")
	}

	return nil
}

// Deserialize reads the Message from an OP_RETURN script.
func Deserialize(buf *bytes.Reader) (uint64, []byte, []byte, *MetaNet, []*EncryptedPayload, []byte,
	error) {

	// Envelope
	_, envelopeData, err := bitcoin.ParsePushDataScript(buf)
	if err != nil {
		return 0, nil, nil, nil, nil, nil, errors.Wrap(err, "Failed to read MetaNet data")
	}

	var envelope protobuf.Envelope
	if len(envelopeData) != 0 {
		if err = proto.Unmarshal(envelopeData, &envelope); err != nil {
			return 0, nil, nil, nil, nil, nil,
				errors.Wrap(err, "Failed envelope protobuf unmarshaling")
		}
	}

	// MetaNet
	var metaNet *MetaNet
	pbMetaNet := envelope.GetMetaNet()
	if pbMetaNet != nil {
		metaNet = &MetaNet{
			index:  pbMetaNet.GetIndex(),
			parent: pbMetaNet.GetParent(),
		}
	}

	// Encrypted payloads
	pbEncryptedPayloads := envelope.GetEncryptedPayloads()
	encryptedPayloads := make([]*EncryptedPayload, 0, len(pbEncryptedPayloads))
	for _, pbEncryptedPayload := range pbEncryptedPayloads {
		var payload EncryptedPayload

		// Sender
		payload.sender = pbEncryptedPayload.GetSender()

		// Receivers
		pbReceivers := pbEncryptedPayload.GetReceivers()
		payload.receivers = make([]*Receiver, 0, len(pbReceivers))
		for _, pbReceiver := range pbReceivers {
			payload.receivers = append(payload.receivers, &Receiver{
				index:        pbReceiver.GetIndex(),
				encryptedKey: pbReceiver.GetEncryptedKey(),
			})
		}

		// Payload
		payload.payload = pbEncryptedPayload.GetPayload()

		encryptedPayloads = append(encryptedPayloads, &payload)
	}

	// Public payload
	_, payload, err := bitcoin.ParsePushDataScript(buf)
	if err != nil {
		return 0, nil, nil, nil, nil, nil, errors.Wrap(err, "Failed to parse payload size")
	}

	return envelope.GetVersion(), envelope.GetType(), envelope.GetIdentifier(), metaNet,
		encryptedPayloads, payload, nil
}
