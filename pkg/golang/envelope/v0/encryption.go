package v0

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/tokenized/smart-contract/pkg/bitcoin"
	"github.com/tokenized/smart-contract/pkg/wire"
)

var (
	ErrDecryptInvalid = errors.New("Decrypt invalid")
)

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

func (ep *EncryptedPayload) SenderPublicKey(tx *wire.MsgTx) (bitcoin.PublicKey, error) {
	if int(ep.sender) >= len(tx.TxIn) {
		return bitcoin.PublicKey{}, fmt.Errorf("Sender index out of range : %d/%d", ep.sender,
			len(tx.TxIn))
	}

	spk, err := bitcoin.PublicKeyFromUnlockingScript(tx.TxIn[ep.sender].SignatureScript)
	if err != nil {
		return bitcoin.PublicKey{}, err
	}

	return bitcoin.PublicKeyFromBytes(spk)
}

func (ep *EncryptedPayload) ReceiverAddresses(tx *wire.MsgTx) ([]bitcoin.RawAddress, error) {
	result := make([]bitcoin.RawAddress, 0, len(ep.receivers))
	for _, receiver := range ep.receivers {
		if int(receiver.index) >= len(tx.TxOut) {
			return nil, fmt.Errorf("Receiver index out of range : %d/%d", receiver.index,
				len(tx.TxOut))
		}

		ra, err := bitcoin.RawAddressFromLockingScript(tx.TxOut[receiver.index].PkScript)
		if err != nil {
			continue
		}

		result = append(result, ra)
	}

	return result, nil
}

func NewEncryptedPayload(payload []byte, tx *wire.MsgTx, senderIndex uint32, sender bitcoin.Key,
	receivers []bitcoin.PublicKey) (*EncryptedPayload, error) {

	result := &EncryptedPayload{sender: senderIndex}
	var encryptionKey []byte

	if len(receivers) == 0 { // Private to sender
		encryptionKey = bitcoin.Sha256(sender.Number())
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
			return nil, errors.New("Receiver output not found")
		}
		result.receivers = []*Receiver{
			&Receiver{index: receiverIndex}, // No encrypted key required since it is derivable.
		}

		// Encryption key is derived using ECDH with sender's private key and receiver's public key.
		secret, err := bitcoin.ECDHSecret(sender, receivers[0])
		if err != nil {
			return nil, err
		}
		encryptionKey = bitcoin.Sha256(secret)

	} else { // Multiple receivers
		// Encryption key is random and encrypted to each receiver.
		encryptionKey = make([]byte, 32)
		_, err := rand.Read(encryptionKey)
		if err != nil {
			return nil, err
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
				return nil, errors.New("Receiver output not found")
			}

			receiverSecret, err := bitcoin.ECDHSecret(sender, receiver)
			if err != nil {
				return nil, err
			}
			receiverKey := bitcoin.Sha256(receiverSecret)

			encryptedKey, err := bitcoin.Encrypt(encryptionKey, receiverKey)
			if err != nil {
				return nil, err
			}

			result.receivers = append(result.receivers, &Receiver{
				index:        receiverIndex,
				encryptedKey: encryptedKey,
			})
		}
	}

	var err error
	result.payload, err = bitcoin.Encrypt(payload, encryptionKey)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// SenderDecrypt decrypts the payload using the sender's private key and a receiver's public key.
func (ep *EncryptedPayload) SenderDecrypt(tx *wire.MsgTx, senderKey bitcoin.Key,
	receiverPubKey bitcoin.PublicKey) ([]byte, error) {

	// Find sender
	if ep.sender >= uint32(len(tx.TxIn)) {
		return nil, errors.New("Sender index out of range")
	}

	senderPubKeyData, err := bitcoin.PublicKeyFromUnlockingScript(tx.TxIn[ep.sender].SignatureScript)
	if err != nil {
		return nil, err
	}

	senderPubKey, err := bitcoin.PublicKeyFromBytes(senderPubKeyData)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(senderPubKey.Bytes(), senderKey.PublicKey().Bytes()) {
		return nil, errors.New("Wrong sender key")
	}

	if len(ep.receivers) == 0 {
		return bitcoin.Decrypt(ep.payload, bitcoin.Sha256(senderKey.Number()))
	}

	if receiverPubKey.IsEmpty() {
		return nil, errors.New("Receiver public key required")
	}

	// Find receiver
	pkh, _ := bitcoin.NewHash20(bitcoin.Hash160(receiverPubKey.Bytes()))
	for _, receiver := range ep.receivers {
		if receiver.index >= uint32(len(tx.TxOut)) {
			continue
		}

		rawAddress, err := bitcoin.RawAddressFromLockingScript(tx.TxOut[receiver.index].PkScript)
		if err != nil {
			continue
		}

		hash, err := rawAddress.GetPublicKeyHash()
		matches := err == nil && hash.Equal(pkh)

		if !matches {
			key, err := rawAddress.GetPublicKey()
			matches = err == nil && key.Equal(receiverPubKey)
		}

		if !matches {
			continue
		}

		if len(receiver.encryptedKey) == 0 {
			if len(ep.receivers) != 1 {
				// For more than one receiver, an encrypted key must be provided.
				return nil, errors.New("Missing encryption key for receiver")
			}

			// Use DH secret
			secret, err := bitcoin.ECDHSecret(senderKey, receiverPubKey)
			if err != nil {
				return nil, err
			}
			encryptionKey := bitcoin.Sha256(secret)

			return bitcoin.Decrypt(ep.payload, encryptionKey)
		} else {
			// Decrypt key using DH key
			secret, err := bitcoin.ECDHSecret(senderKey, receiverPubKey)
			if err != nil {
				return nil, err
			}
			dhKey := bitcoin.Sha256(secret)

			encryptionKey, err := bitcoin.Decrypt(receiver.encryptedKey, dhKey)
			if err != nil {
				return nil, err
			}

			return bitcoin.Decrypt(ep.payload, encryptionKey)
		}
	}

	return nil, errors.New("Matching receiver not found")
}

// ReceiverDecrypt decrypts the payload using the receiver's private key.
func (ep *EncryptedPayload) ReceiverDecrypt(tx *wire.MsgTx, receiverKey bitcoin.Key) ([]byte, error) {
	if len(ep.receivers) == 0 {
		return nil, errors.New("No receivers")
	}

	// Find sender
	if ep.sender >= uint32(len(tx.TxIn)) {
		return nil, errors.New("Sender index out of range")
	}

	senderPubKeyData, err := bitcoin.PublicKeyFromUnlockingScript(tx.TxIn[ep.sender].SignatureScript)
	if err != nil {
		return nil, err
	}

	senderPubKey, err := bitcoin.PublicKeyFromBytes(senderPubKeyData)
	if err != nil {
		return nil, err
	}

	// Find receiver
	pk := receiverKey.PublicKey()
	pkh, _ := bitcoin.NewHash20(bitcoin.Hash160(pk.Bytes()))
	for _, receiver := range ep.receivers {
		if receiver.index >= uint32(len(tx.TxOut)) {
			continue
		}

		rawAddress, err := bitcoin.RawAddressFromLockingScript(tx.TxOut[receiver.index].PkScript)
		if err != nil {
			continue
		}

		hash, err := rawAddress.GetPublicKeyHash()
		matches := err == nil && hash.Equal(pkh)

		if !matches {
			key, err := rawAddress.GetPublicKey()
			matches = err == nil && key.Equal(pk)
		}

		if !matches {
			continue
		}

		if len(receiver.encryptedKey) == 0 {
			if len(ep.receivers) != 1 {
				// For more than one receiver, an encrypted key must be provided.
				return nil, errors.New("Missing encryption key for receiver")
			}

			// Use DH secret
			secret, err := bitcoin.ECDHSecret(receiverKey, senderPubKey)
			if err != nil {
				return nil, err
			}
			encryptionKey := bitcoin.Sha256(secret)

			return bitcoin.Decrypt(ep.payload, encryptionKey)
		} else {
			// Decrypt key using DH key
			secret, err := bitcoin.ECDHSecret(receiverKey, senderPubKey)
			if err != nil {
				return nil, err
			}
			dhKey := bitcoin.Sha256(secret)

			encryptionKey, err := bitcoin.Decrypt(receiver.encryptedKey, dhKey)
			if err != nil {
				return nil, err
			}

			return bitcoin.Decrypt(ep.payload, encryptionKey)
		}
	}

	return nil, errors.New("Matching receiver not found")
}
