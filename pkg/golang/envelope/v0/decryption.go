package v0

import (
	"bytes"
	"fmt"

	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"

	"github.com/pkg/errors"
)

var (
	ErrDecryptInvalid = errors.New("Decrypt invalid")
)

func (ep *EncryptedPayload) EncryptionType() uint32 {
	return ep.encryptionType
}

func (ep *EncryptedPayload) SenderPublicKey(tx *wire.MsgTx) (bitcoin.PublicKey, error) {
	if int(ep.sender) >= len(tx.TxIn) {
		return bitcoin.PublicKey{}, fmt.Errorf("Sender index out of range : %d/%d", ep.sender,
			len(tx.TxIn))
	}

	spk, err := bitcoin.PublicKeyFromUnlockingScript(tx.TxIn[ep.sender].UnlockingScript)
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

		ra, err := bitcoin.RawAddressFromLockingScript(tx.TxOut[receiver.index].LockingScript)
		if err != nil {
			continue
		}

		result = append(result, ra)
	}

	return result, nil
}

// IndirectDecrypt decrypts the payload using the specified secret.
func (ep *EncryptedPayload) IndirectDecrypt(encryptionKey bitcoin.Hash32) ([]byte, error) {
	return bitcoin.Decrypt(ep.payload, encryptionKey.Bytes())
}

// SenderDecrypt decrypts the payload using the sender's private key and a receiver's public key.
func (ep *EncryptedPayload) SenderDecrypt(tx *wire.MsgTx, senderKey bitcoin.Key,
	receiverPubKey bitcoin.PublicKey) ([]byte, error) {
	payload, _, err := ep.SenderDecryptKey(tx, senderKey, receiverPubKey)
	return payload, err
}

// SenderDecryptKey decrypts the payload using the sender's private key and a receiver's public key.
func (ep *EncryptedPayload) SenderDecryptKey(tx *wire.MsgTx, senderKey bitcoin.Key,
	receiverPubKey bitcoin.PublicKey) ([]byte, bitcoin.Hash32, error) {

	if ep.encryptionType != 0 {
		return nil, bitcoin.Hash32{}, errors.Wrap(ErrDecryptInvalid, "Indirect")
	}

	// Find sender
	if ep.sender >= uint32(len(tx.TxIn)) {
		return nil, bitcoin.Hash32{}, errors.New("Sender index out of range")
	}

	senderPubKeyData, err := bitcoin.PublicKeyFromUnlockingScript(tx.TxIn[ep.sender].UnlockingScript)
	if err != nil {
		return nil, bitcoin.Hash32{}, err
	}

	senderPubKey, err := bitcoin.PublicKeyFromBytes(senderPubKeyData)
	if err != nil {
		return nil, bitcoin.Hash32{}, err
	}

	if !bytes.Equal(senderPubKey.Bytes(), senderKey.PublicKey().Bytes()) {
		return nil, bitcoin.Hash32{}, errors.New("Wrong sender key")
	}

	if len(ep.receivers) == 0 {
		key, _ := bitcoin.NewHash32(bitcoin.Sha256(senderKey.Number()))
		payload, err := bitcoin.Decrypt(ep.payload, key.Bytes())
		return payload, *key, err
	}

	if receiverPubKey.IsEmpty() {
		return nil, bitcoin.Hash32{}, errors.New("Receiver public key required")
	}

	// Find receiver
	pkh, _ := bitcoin.NewHash20(bitcoin.Hash160(receiverPubKey.Bytes()))
	for _, receiver := range ep.receivers {
		if receiver.index >= uint32(len(tx.TxOut)) {
			continue
		}

		rawAddress, err := bitcoin.RawAddressFromLockingScript(tx.TxOut[receiver.index].LockingScript)
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
				return nil, bitcoin.Hash32{}, errors.New("Missing encryption key for receiver")
			}

			// Use DH secret
			secret, err := bitcoin.ECDHSecret(senderKey, receiverPubKey)
			if err != nil {
				return nil, bitcoin.Hash32{}, err
			}
			encryptionKey, _ := bitcoin.NewHash32(bitcoin.Sha256(secret))

			payload, err := bitcoin.Decrypt(ep.payload, encryptionKey.Bytes())
			return payload, *encryptionKey, err
		} else {
			// Decrypt key using DH key
			secret, err := bitcoin.ECDHSecret(senderKey, receiverPubKey)
			if err != nil {
				return nil, bitcoin.Hash32{}, err
			}
			dhKey := bitcoin.Sha256(secret)

			encryptionKey, err := bitcoin.Decrypt(receiver.encryptedKey, dhKey)
			if err != nil {
				return nil, bitcoin.Hash32{}, err
			}

			key, _ := bitcoin.NewHash32(encryptionKey)

			payload, err := bitcoin.Decrypt(ep.payload, encryptionKey)
			return payload, *key, err
		}
	}

	return nil, bitcoin.Hash32{}, errors.New("Matching receiver not found")
}

// ReceiverDecrypt decrypts the payload using the receiver's private key.
func (ep *EncryptedPayload) ReceiverDecrypt(tx *wire.MsgTx, receiverKey bitcoin.Key) ([]byte, error) {
	result, _, err := ep.ReceiverDecryptKey(tx, receiverKey)
	return result, err
}

// ReceiverDecryptKey decrypts the payload using the receiver's private key and returns the
//   encryption key.
func (ep *EncryptedPayload) ReceiverDecryptKey(tx *wire.MsgTx, receiverKey bitcoin.Key) ([]byte, bitcoin.Hash32, error) {

	if ep.encryptionType != 0 {
		return nil, bitcoin.Hash32{}, errors.Wrap(ErrDecryptInvalid, "Indirect")
	}

	if len(ep.receivers) == 0 {
		return nil, bitcoin.Hash32{}, errors.New("No receivers")
	}

	// Find sender
	if ep.sender >= uint32(len(tx.TxIn)) {
		return nil, bitcoin.Hash32{}, errors.New("Sender index out of range")
	}

	senderPubKeyData, err := bitcoin.PublicKeyFromUnlockingScript(tx.TxIn[ep.sender].UnlockingScript)
	if err != nil {
		return nil, bitcoin.Hash32{}, err
	}

	senderPubKey, err := bitcoin.PublicKeyFromBytes(senderPubKeyData)
	if err != nil {
		return nil, bitcoin.Hash32{}, err
	}

	// Find receiver
	pk := receiverKey.PublicKey()
	pkh, _ := bitcoin.NewHash20(bitcoin.Hash160(pk.Bytes()))
	for _, receiver := range ep.receivers {
		if receiver.index >= uint32(len(tx.TxOut)) {
			continue
		}

		rawAddress, err := bitcoin.RawAddressFromLockingScript(tx.TxOut[receiver.index].LockingScript)
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
				return nil, bitcoin.Hash32{}, errors.New("Missing encryption key for receiver")
			}

			// Use DH secret
			secret, err := bitcoin.ECDHSecret(receiverKey, senderPubKey)
			if err != nil {
				return nil, bitcoin.Hash32{}, err
			}
			encryptionKey, _ := bitcoin.NewHash32(bitcoin.Sha256(secret))

			result, err := bitcoin.Decrypt(ep.payload, encryptionKey.Bytes())
			return result, *encryptionKey, err
		} else {
			// Decrypt key using DH key
			secret, err := bitcoin.ECDHSecret(receiverKey, senderPubKey)
			if err != nil {
				return nil, bitcoin.Hash32{}, err
			}
			dhKey := bitcoin.Sha256(secret)

			encryptionKey, err := bitcoin.Decrypt(receiver.encryptedKey, dhKey)
			if err != nil {
				return nil, bitcoin.Hash32{}, err
			}

			key, err := bitcoin.NewHash32(encryptionKey)
			if err != nil {
				return nil, bitcoin.Hash32{}, err
			}

			result, err := bitcoin.Decrypt(ep.payload, encryptionKey)
			return result, *key, err
		}
	}

	return nil, bitcoin.Hash32{}, errors.New("Matching receiver not found")
}
