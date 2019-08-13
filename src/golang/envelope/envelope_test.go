package envelope

import (
	"bytes"
	"testing"

	"github.com/tokenized/envelope/src/golang/envelope/v0"
	"github.com/tokenized/envelope/src/golang/envelope/v0/protobuf"
	"github.com/tokenized/smart-contract/pkg/bitcoin"
	"github.com/tokenized/smart-contract/pkg/wire"

	"github.com/golang/protobuf/proto"
)

var retentionTests = []struct {
	protocol    []byte
	version     uint64
	payloadType []byte
	identifier  []byte
	payload     []byte
}{
	{
		protocol:    []byte("tokenized"),
		version:     1,
		payloadType: nil,
		identifier:  nil,
		payload:     []byte("Test data 1"),
	},
	{
		protocol:    []byte("test"),
		version:     1,
		payloadType: nil,
		identifier:  nil,
		payload:     []byte("5"),
	},
	{
		protocol:    []byte{0xbe, 0xef},
		version:     1,
		payloadType: []byte("beef"),
		identifier:  nil,
		payload:     nil,
	},
	{
		protocol:    []byte{0xbe, 0xef},
		version:     1,
		payloadType: nil,
		identifier:  []byte("beef"),
		payload:     nil,
	},
}

func TestRetention(t *testing.T) {
	for i, test := range retentionTests {
		message := v0.NewMessage(test.protocol, test.version, test.payload)

		if len(test.payloadType) > 0 {
			message.SetPayloadType(test.payloadType)
		}
		if len(test.identifier) > 0 {
			message.SetPayloadIdentifier(test.identifier)
		}

		var buf bytes.Buffer
		err := message.Serialize(&buf)
		if err != nil {
			t.Fatalf("Test %d Failed Serialize : %s", i, err)
		}

		reader := bytes.NewReader(buf.Bytes())
		read, err := Deserialize(reader)
		if err != nil {
			t.Fatalf("Test %d Failed Deserialize : %s", i, err)
		}

		if !bytes.Equal(test.protocol, read.PayloadProtocol()) {
			t.Fatalf("Test %d protocol wasn't retained : want 0x%x, got 0x%x", i+1, test.protocol, read.PayloadProtocol())
		}
		if test.version != read.PayloadVersion() {
			t.Fatalf("Test %d version wasn't retained : want %d, got %d", i+1, test.version, read.PayloadVersion())
		}
		if !bytes.Equal(test.payloadType, read.PayloadType()) {
			t.Fatalf("Test %d payload type wasn't retained : want 0x%x, got 0x%x", i+1, test.payloadType, read.PayloadType())
		}
		if !bytes.Equal(test.identifier, read.PayloadIdentifier()) {
			t.Fatalf("Test %d identifier wasn't retained : want 0x%x, got 0x%x", i+1, test.identifier, read.PayloadIdentifier())
		}
		if !bytes.Equal(test.payload, read.Payload()) {
			t.Fatalf("Test %d payload wasn't retained : want 0x%x, got 0x%x", i+1, test.payload, read.Payload())
		}
	}
}

var encryptionTests = []struct {
	protocol         []byte
	version          uint64
	payload          []byte
	encryptedPayload []byte
}{
	{
		protocol:         []byte("tokenized"),
		version:          1,
		payload:          []byte("Test data 1"),
		encryptedPayload: []byte("Encrypted Data 234"), // more than aes block size of 16
	},
	{
		protocol:         []byte("test"),
		version:          1,
		payload:          []byte("5"),
		encryptedPayload: []byte(""), // empty
	},
	{
		protocol:         []byte{0xbe, 0xef},
		version:          1,
		payload:          nil,
		encryptedPayload: nil,
	},
	{
		protocol:         []byte{0xbe, 0xef},
		version:          1,
		payload:          nil,
		encryptedPayload: []byte("test"), // less than aes block size of 16
	},
	{
		protocol:         []byte{0xbe, 0xef},
		version:          1,
		payload:          nil,
		encryptedPayload: []byte("testtesttesttest"), // exactly block size
	},
	{
		protocol:         []byte{0xbe, 0xef},
		version:          1,
		payload:          nil,
		encryptedPayload: []byte{0xff},
	},
	{
		protocol:         []byte{0xbe, 0xef},
		version:          1,
		payload:          nil,
		encryptedPayload: []byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	},
	{
		protocol:         []byte{0xbe, 0xef},
		version:          1,
		payload:          nil,
		encryptedPayload: []byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff},
	},
	{
		protocol:         []byte{0xbe, 0xef},
		version:          1,
		payload:          nil,
		encryptedPayload: []byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff},
	},
	{
		protocol:         []byte{0xbe, 0xef},
		version:          1,
		payload:          nil,
		encryptedPayload: []byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00},
	},
}

func TestEncryptionNoReceiver(t *testing.T) {
	for i, test := range encryptionTests {
		message := v0.NewMessage(test.protocol, test.version, test.payload)
		sender, err := bitcoin.GenerateKeyS256(bitcoin.TestNet)

		var fakeScriptBuf bytes.Buffer
		err = bitcoin.WritePushDataScript(&fakeScriptBuf, sender.PublicKey().Bytes())
		if err != nil {
			t.Fatalf("Test %d add public key to script failed : %s", i+1, err)
		}
		err = bitcoin.WritePushDataScript(&fakeScriptBuf, []byte("fake signature"))
		if err != nil {
			t.Fatalf("Test %d add signature to script failed : %s", i+1, err)
		}

		tx := wire.NewMsgTx(2)
		if err = addFakeInput(tx, sender); err != nil {
			t.Fatalf("Test %d failed to add input : %s", i+1, err)
		}

		err = message.AddEncryptedPayload(test.encryptedPayload, tx, 0, sender, nil)
		if err != nil {
			t.Fatalf("Test %d add encrypted payload failed : %s", i+1, err)
		}

		var buf bytes.Buffer
		err = message.Serialize(&buf)
		if err != nil {
			t.Fatalf("Test %d failed serialize : %s", i, err)
		}

		reader := bytes.NewReader(buf.Bytes())
		baseRead, err := Deserialize(reader)
		if err != nil {
			t.Fatalf("Test %d failed deserialize : %s", i, err)
		}
		read, ok := baseRead.(*v0.Message)
		if !ok {
			t.Fatalf("Test %d failed to convert read to v0 message", i+1)
		}

		if read.EncryptedPayloadCount() != 1 {
			t.Fatalf("Test %d wrong amount of encrypted payloads : %d", i, read.EncryptedPayloadCount())
		}

		encryptedPayload := read.EncryptedPayload(0)
		encPayload, err := encryptedPayload.SenderDecrypt(tx, sender, nil)
		if err != nil {
			t.Fatalf("Test %d failed decrypt : %s", i, err)
		}

		if !bytes.Equal(test.encryptedPayload, encPayload) {
			t.Fatalf("Test %d encrypted payload doesn't match :\nwant 0x%x\ngot  0x%x", i+1,
				test.encryptedPayload, encPayload)
		}
	}
}

func TestEncryptionSingleReceiver(t *testing.T) {
	for i, test := range encryptionTests {
		message := v0.NewMessage(test.protocol, test.version, test.payload)
		sender, err := bitcoin.GenerateKeyS256(bitcoin.TestNet)
		receiver, err := bitcoin.GenerateKeyS256(bitcoin.TestNet)

		tx := wire.NewMsgTx(2)
		if err = addFakeInput(tx, sender); err != nil {
			t.Fatalf("Test %d failed to add input : %s", i+1, err)
		}
		if err = addFakeOutput(tx, receiver); err != nil {
			t.Fatalf("Test %d failed to add output : %s", i+1, err)
		}

		err = message.AddEncryptedPayload(test.encryptedPayload, tx, 0, sender,
			[]bitcoin.PublicKey{receiver.PublicKey()})
		if err != nil {
			t.Fatalf("Test %d add encrypted payload failed : %s", i+1, err)
		}

		var buf bytes.Buffer
		err = message.Serialize(&buf)
		if err != nil {
			t.Fatalf("Test %d failed serialize : %s", i, err)
		}

		reader := bytes.NewReader(buf.Bytes())
		baseRead, err := Deserialize(reader)
		if err != nil {
			t.Fatalf("Test %d failed deserialize : %s", i, err)
		}
		read, ok := baseRead.(*v0.Message)
		if !ok {
			t.Fatalf("Test %d failed to convert read to v0 message", i+1)
		}

		if read.EncryptedPayloadCount() != 1 {
			t.Fatalf("Test %d wrong amount of encrypted payloads : %d", i, read.EncryptedPayloadCount())
		}

		encryptedPayload := read.EncryptedPayload(0)
		encPayload, err := encryptedPayload.SenderDecrypt(tx, sender, receiver.PublicKey())
		if err != nil {
			t.Fatalf("Test %d failed decrypt : %s", i, err)
		}

		if !bytes.Equal(test.encryptedPayload, encPayload) {
			t.Fatalf("Test %d encrypted payload doesn't match :\nwant 0x%x\ngot  0x%x", i+1,
				test.encryptedPayload, encPayload)
		}
	}
}

func TestEncryptionMultiReceiver(t *testing.T) {
	for i, test := range encryptionTests {
		message := v0.NewMessage(test.protocol, test.version, test.payload)
		sender, err := bitcoin.GenerateKeyS256(bitcoin.TestNet)
		receiver1, err := bitcoin.GenerateKeyS256(bitcoin.TestNet)
		receiver2, err := bitcoin.GenerateKeyS256(bitcoin.TestNet)

		tx := wire.NewMsgTx(2)
		if err = addFakeInput(tx, sender); err != nil {
			t.Fatalf("Test %d failed to add input : %s", i+1, err)
		}
		if err = addFakeOutput(tx, receiver1); err != nil {
			t.Fatalf("Test %d failed to add output : %s", i+1, err)
		}
		if err = addFakeOutput(tx, receiver2); err != nil {
			t.Fatalf("Test %d failed to add output : %s", i+1, err)
		}

		err = message.AddEncryptedPayload(test.encryptedPayload, tx, 0, sender,
			[]bitcoin.PublicKey{receiver1.PublicKey(), receiver2.PublicKey()})
		if err != nil {
			t.Fatalf("Test %d add encrypted payload failed : %s", i+1, err)
		}

		var buf bytes.Buffer
		err = message.Serialize(&buf)
		if err != nil {
			t.Fatalf("Test %d failed serialize : %s", i, err)
		}

		reader := bytes.NewReader(buf.Bytes())
		baseRead, err := Deserialize(reader)
		if err != nil {
			t.Fatalf("Test %d failed deserialize : %s", i, err)
		}
		read, ok := baseRead.(*v0.Message)
		if !ok {
			t.Fatalf("Test %d failed to convert read to v0 message", i+1)
		}

		if read.EncryptedPayloadCount() != 1 {
			t.Fatalf("Test %d wrong amount of encrypted payloads : %d", i, read.EncryptedPayloadCount())
		}

		encryptedPayload := read.EncryptedPayload(0)
		encPayload, err := encryptedPayload.SenderDecrypt(tx, sender, receiver2.PublicKey())
		if err != nil {
			t.Fatalf("Test %d failed decrypt : %s", i, err)
		}

		if !bytes.Equal(test.encryptedPayload, encPayload) {
			t.Fatalf("Test %d encrypted payload doesn't match :\nwant 0x%x\ngot  0x%x", i+1,
				test.encryptedPayload, encPayload)
		}
	}
}

func TestEncryptionProtobuf(t *testing.T) {
	mnIndex := &protobuf.MetaNet{
		Index: 2,
	}
	mnParent := &protobuf.MetaNet{
		Parent: []byte("01234567890123456789012345678901"),
	}
	encryptedPayload, err := proto.Marshal(mnIndex)
	if err != nil {
		t.Fatalf("Failed to serialize metanet index : %s", err)
	}
	payload, err := proto.Marshal(mnParent)
	if err != nil {
		t.Fatalf("Failed to serialize metanet parent : %s", err)
	}

	message := v0.NewMessage([]byte("test"), 0, payload)
	sender, err := bitcoin.GenerateKeyS256(bitcoin.TestNet)
	receiver1, err := bitcoin.GenerateKeyS256(bitcoin.TestNet)
	receiver2, err := bitcoin.GenerateKeyS256(bitcoin.TestNet)

	tx := wire.NewMsgTx(2)
	if err = addFakeInput(tx, sender); err != nil {
		t.Fatalf("Test failed to add input : %s", err)
	}
	if err = addFakeOutput(tx, receiver1); err != nil {
		t.Fatalf("Test failed to add output : %s", err)
	}
	if err = addFakeOutput(tx, receiver2); err != nil {
		t.Fatalf("Test failed to add output : %s", err)
	}

	err = message.AddEncryptedPayload(encryptedPayload, tx, 0, sender,
		[]bitcoin.PublicKey{receiver1.PublicKey(), receiver2.PublicKey()})
	if err != nil {
		t.Fatalf("Test add encrypted payload failed : %s", err)
	}

	var buf bytes.Buffer
	err = message.Serialize(&buf)
	if err != nil {
		t.Fatalf("Test failed serialize : %s", err)
	}

	reader := bytes.NewReader(buf.Bytes())
	baseRead, err := Deserialize(reader)
	if err != nil {
		t.Fatalf("Test failed deserialize : %s", err)
	}
	read, ok := baseRead.(*v0.Message)
	if !ok {
		t.Fatalf("Test failed to convert read to v0 message")
	}

	if read.EncryptedPayloadCount() != 1 {
		t.Fatalf("Test wrong amount of encrypted payloads : %d", read.EncryptedPayloadCount())
	}

	readEncryptedPayload := read.EncryptedPayload(0)
	encPayload, err := readEncryptedPayload.SenderDecrypt(tx, sender, receiver2.PublicKey())
	if err != nil {
		t.Fatalf("Test failed decrypt : %s", err)
	}

	if !bytes.Equal(encryptedPayload, encPayload) {
		t.Fatalf("Test encrypted payload doesn't match :\nwant 0x%x\ngot  0x%x", encryptedPayload, encPayload)
	}

	compositePayload := append(encPayload, read.Payload()...)

	var readMN protobuf.MetaNet
	if err = proto.Unmarshal(compositePayload, &readMN); err != nil {
		t.Fatalf("Test failed unmarshal protobuf : %s", err)
	}

	if readMN.GetIndex() != mnIndex.GetIndex() {
		t.Fatalf("Test failed MetaNet index mismatch : got %d want %d", readMN.GetIndex(), mnIndex.GetIndex())
	}

	if !bytes.Equal(readMN.GetParent(), mnParent.GetParent()) {
		t.Fatalf("Test failed MetaNet index mismatch : got %x want %x", readMN.GetParent(), mnParent.GetParent())
	}
}

func addFakeInput(tx *wire.MsgTx, key bitcoin.Key) error {
	var fakeScriptBuf bytes.Buffer
	err := bitcoin.WritePushDataScript(&fakeScriptBuf, key.PublicKey().Bytes())
	if err != nil {
		return err
	}
	err = bitcoin.WritePushDataScript(&fakeScriptBuf, []byte("fake signature"))
	if err != nil {
		return err
	}
	tx.TxIn = append(tx.TxIn, &wire.TxIn{
		SignatureScript: fakeScriptBuf.Bytes(),
		Sequence:        0xffffffff,
	})
	return nil
}

func addFakeOutput(tx *wire.MsgTx, key bitcoin.Key) error {
	address, err := bitcoin.NewRawAddressPKH(bitcoin.Hash160(key.PublicKey().Bytes()))
	if err != nil {
		return err
	}
	var fakeScriptBuf bytes.Buffer
	err = bitcoin.WritePushDataScript(&fakeScriptBuf, key.PublicKey().Bytes())
	if err != nil {
		return err
	}
	err = bitcoin.WritePushDataScript(&fakeScriptBuf, []byte("fake signature"))
	if err != nil {
		return err
	}
	tx.TxOut = append(tx.TxOut, &wire.TxOut{
		PkScript: address.LockingScript(),
		Value:    100,
	})
	return nil
}
