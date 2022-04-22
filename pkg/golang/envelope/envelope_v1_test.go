package envelope

import (
	"bytes"
	"testing"

	"github.com/tokenized/envelope/pkg/golang/envelope/base"
	v1 "github.com/tokenized/envelope/pkg/golang/envelope/v1"
)

var v1RetentionTests = []struct {
	protocolIDs base.ProtocolIDs
	payloads    [][]byte
}{
	{
		protocolIDs: base.ProtocolIDs{base.ProtocolID("tokenized")},
		payloads:    [][]byte{[]byte("T1"), []byte("Test data 1")},
	},
	{
		protocolIDs: base.ProtocolIDs{base.ProtocolID("test")},
		payloads:    [][]byte{[]byte("5")},
	},
	{
		protocolIDs: base.ProtocolIDs{base.ProtocolID{0xbe, 0xef}},
		payloads:    nil,
	},
	{
		protocolIDs: base.ProtocolIDs{base.ProtocolID{0xbe, 0xef}},
		payloads:    nil,
	},
}

func TestRetentionV1(t *testing.T) {
	for i, test := range v1RetentionTests {
		message := v1.NewMessage(test.protocolIDs, test.payloads)

		var buf bytes.Buffer
		err := message.Serialize(&buf)
		if err != nil {
			t.Fatalf("Test %d Failed Serialize : %s", i, err)
		}

		reader := bytes.NewReader(buf.Bytes())
		readBase, err := Deserialize(reader)
		if err != nil {
			t.Fatalf("Test %d Failed Deserialize : %s", i, err)
		}

		read, ok := readBase.(*v1.Message)
		if !ok {
			t.Fatalf("Wrong message type")
		}

		protocolIDs := read.PayloadProtocols()
		if len(protocolIDs) != len(test.protocolIDs) {
			t.Fatalf("Wrong protocol ID count : got %d, want %d", len(protocolIDs),
				len(test.protocolIDs))
		}

		payloadCount := read.PayloadCount()
		if payloadCount != len(test.payloads) {
			t.Fatalf("Wrong payload count : got %d, want %d", payloadCount, len(test.payloads))
		}

		for i, protocolID := range protocolIDs {
			if !bytes.Equal(protocolID, test.protocolIDs[i]) {
				t.Errorf("Wrong protocol ID %d : \ngot  : %x\nwant : %x", i, protocolID,
					test.protocolIDs[i])
			}

			t.Logf("Verified protocol ID %d : %x", i, protocolID)
		}

		for i := 0; i < payloadCount; i++ {
			payload := read.PayloadAt(i)
			if !bytes.Equal(payload, test.payloads[i]) {
				t.Errorf("Wrong payload %d : \ngot  : %x\nwant : %x", i, payload,
					test.payloads[i])
			}

			t.Logf("Verified payload %d : %x", i, payload)
		}
	}
}
