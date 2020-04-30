package v0

import (
	"crypto/rand"
	"errors"

	"github.com/tokenized/smart-contract/pkg/bitcoin"
	"github.com/tokenized/smart-contract/pkg/wire"
)

// NewEncryptedPayload creates an encrypted payload. The encryption information is contained in the
//   tx. A private key of the sender or one of the receivers is necessary to decrypt.
// If there are more than one receivers. A random encryption secret is generated and encrypted to
//   each receiver.
func NewEncryptedPayload(payload []byte, tx *wire.MsgTx, senderIndex uint32, sender bitcoin.Key,
	receivers []bitcoin.PublicKey) (*EncryptedPayload, error) {
	result, _, err := NewEncryptedPayloadDirect(payload, tx, senderIndex, sender, receivers)
	return result, err
}

// NewEncryptedPayloadDirect creates an encrypted payload.
// Returns:
//   encrypted payload
//   encryption key
//   error, if there is one
func NewEncryptedPayloadDirect(payload []byte, tx *wire.MsgTx, senderIndex uint32, sender bitcoin.Key,
	receivers []bitcoin.PublicKey) (*EncryptedPayload, bitcoin.Hash32, error) {

	result := &EncryptedPayload{sender: senderIndex}
	var encryptionKey *bitcoin.Hash32

	if len(receivers) == 0 { // Private to sender
		encryptionKey, _ = bitcoin.NewHash32(bitcoin.Sha256(sender.Number()))
	} else if len(receivers) == 1 { // One receiver
		// Find receiver's output
		pkh, _ := bitcoin.NewHash20(bitcoin.Hash160(receivers[0].Bytes()))
		receiverIndex := uint32(0)
		found := false
		for index, output := range tx.TxOut {
			rawAddress, err := bitcoin.RawAddressFromLockingScript(output.PkScript)
			if err != nil {
				continue
			}

			hash, err := rawAddress.GetPublicKeyHash()
			if err == nil && hash.Equal(pkh) {
				found = true
				receiverIndex = uint32(index)
				break
			}

			key, err := rawAddress.GetPublicKey()
			if err == nil && key.Equal(receivers[0]) {
				found = true
				receiverIndex = uint32(index)
				break
			}
		}
		if !found {
			return nil, bitcoin.Hash32{}, errors.New("Receiver output not found")
		}
		result.receivers = []*Receiver{
			&Receiver{index: receiverIndex}, // No encrypted key required since it is derivable.
		}

		// Encryption key is derived using ECDH with sender's private key and receiver's public key.
		secret, err := bitcoin.ECDHSecret(sender, receivers[0])
		if err != nil {
			return nil, bitcoin.Hash32{}, err
		}
		encryptionKey, _ = bitcoin.NewHash32(bitcoin.Sha256(secret))

	} else { // Multiple receivers
		// Encryption key is random and encrypted to each receiver.
		encryptionKey = &bitcoin.Hash32{}
		_, err := rand.Read(encryptionKey[:])
		if err != nil {
			return nil, bitcoin.Hash32{}, err
		}

		// Find each receiver's output and encrypt key using their DH secret.
		for _, receiver := range receivers {
			pkh, _ := bitcoin.NewHash20(bitcoin.Hash160(receiver.Bytes()))
			receiverIndex := uint32(0)
			found := false
			for index, output := range tx.TxOut {
				rawAddress, err := bitcoin.RawAddressFromLockingScript(output.PkScript)
				if err != nil {
					continue
				}

				hash, err := rawAddress.GetPublicKeyHash()
				if err == nil && hash.Equal(pkh) {
					found = true
					receiverIndex = uint32(index)
					break
				}

				key, err := rawAddress.GetPublicKey()
				if err == nil && key.Equal(receivers[0]) {
					found = true
					receiverIndex = uint32(index)
					break
				}
			}
			if !found {
				return nil, bitcoin.Hash32{}, errors.New("Receiver output not found")
			}

			receiverSecret, err := bitcoin.ECDHSecret(sender, receiver)
			if err != nil {
				return nil, bitcoin.Hash32{}, err
			}
			receiverKey := bitcoin.Sha256(receiverSecret)

			encryptedKey, err := bitcoin.Encrypt(encryptionKey.Bytes(), receiverKey)
			if err != nil {
				return nil, bitcoin.Hash32{}, err
			}

			result.receivers = append(result.receivers, &Receiver{
				index:        receiverIndex,
				encryptedKey: encryptedKey,
			})
		}
	}

	var err error
	result.payload, err = bitcoin.Encrypt(payload, encryptionKey.Bytes())
	if err != nil {
		return nil, bitcoin.Hash32{}, err
	}

	return result, *encryptionKey, nil
}

// NewEncryptedPayloadIndirect creates an encryped payload that is encrypted with the specified
//   key instead of with keys in the message.
func NewEncryptedPayloadIndirect(payload []byte, tx *wire.MsgTx, key bitcoin.Hash32) (*EncryptedPayload, error) {

	result := &EncryptedPayload{encryptionType: 1}

	var err error
	result.payload, err = bitcoin.Encrypt(payload, key.Bytes())
	if err != nil {
		return nil, err
	}

	return result, nil
}
