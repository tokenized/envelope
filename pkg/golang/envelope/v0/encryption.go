package v0

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/tokenized/smart-contract/pkg/bitcoin"
	"github.com/tokenized/smart-contract/pkg/wire"

	"github.com/btcsuite/btcd/btcec"
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

func NewEncryptedPayload(payload []byte, tx *wire.MsgTx, senderIndex uint32, sender bitcoin.Key,
	receivers []bitcoin.PublicKey) (*EncryptedPayload, error) {

	result := &EncryptedPayload{sender: senderIndex}
	var encryptionKey []byte

	if len(receivers) == 0 { // Private to sender
		encryptionKey = bitcoin.Sha256(sender.Number())
	} else if len(receivers) == 1 { // One receiver
		// Find receiver's output
		pkh := bitcoin.Hash160(receivers[0].Bytes())
		receiverIndex := uint32(0)
		found := false
		for index, output := range tx.TxOut {
			rawAddress, err := bitcoin.RawAddressFromLockingScript(output.PkScript)
			if err != nil {
				continue
			}
			if rawAddress.Type() != bitcoin.ScriptTypePKH {
				continue
			}
			hash, _ := rawAddress.Hash()
			if bytes.Equal(pkh, hash.Bytes()) {
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
		secret, err := ecdhSecret(sender, receivers[0])
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
			pkh := bitcoin.Hash160(receiver.Bytes())
			receiverIndex := uint32(0)
			found := false
			for index, output := range tx.TxOut {
				rawAddress, err := bitcoin.RawAddressFromLockingScript(output.PkScript)
				if err != nil {
					continue
				}
				if rawAddress.Type() != bitcoin.ScriptTypePKH {
					continue
				}
				hash, _ := rawAddress.Hash()
				if bytes.Equal(pkh, hash.Bytes()) {
					found = true
					receiverIndex = uint32(index)
					break
				}
			}
			if !found {
				return nil, errors.New("Receiver output not found")
			}

			receiverSecret, err := ecdhSecret(sender, receiver)
			if err != nil {
				return nil, err
			}
			receiverKey := bitcoin.Sha256(receiverSecret)

			encryptedKey, err := encrypt(encryptionKey, receiverKey)
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
	result.payload, err = encrypt(payload, encryptionKey)
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
		return decrypt(ep.payload, bitcoin.Sha256(senderKey.Number()))
	}

	if receiverPubKey.IsEmpty() {
		return nil, errors.New("Receiver public key required")
	}

	// Find receiver
	pkh := bitcoin.Hash160(receiverPubKey.Bytes())
	for _, receiver := range ep.receivers {
		if receiver.index >= uint32(len(tx.TxOut)) {
			continue
		}

		rawAddress, err := bitcoin.RawAddressFromLockingScript(tx.TxOut[receiver.index].PkScript)
		if err != nil {
			continue
		}

		if rawAddress.Type() != bitcoin.ScriptTypePKH {
			continue
		}

		hash, _ := rawAddress.Hash()
		if bytes.Equal(pkh, hash.Bytes()) {
			if len(receiver.encryptedKey) == 0 {
				if len(ep.receivers) != 1 {
					// For more than one receiver, an encrypted key must be provided.
					return nil, errors.New("Missing encryption key for receiver")
				}

				// Use DH secret
				secret, err := ecdhSecret(senderKey, receiverPubKey)
				if err != nil {
					return nil, err
				}
				encryptionKey := bitcoin.Sha256(secret)

				return decrypt(ep.payload, encryptionKey)
			} else {
				// Decrypt key using DH key
				secret, err := ecdhSecret(senderKey, receiverPubKey)
				if err != nil {
					return nil, err
				}
				dhKey := bitcoin.Sha256(secret)

				encryptionKey, err := decrypt(receiver.encryptedKey, dhKey)
				if err != nil {
					return nil, err
				}

				return decrypt(ep.payload, encryptionKey)
			}
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
	pkh := bitcoin.Hash160(receiverKey.PublicKey().Bytes())
	for _, receiver := range ep.receivers {
		if receiver.index >= uint32(len(tx.TxOut)) {
			continue
		}

		rawAddress, err := bitcoin.RawAddressFromLockingScript(tx.TxOut[receiver.index].PkScript)
		if err != nil {
			continue
		}

		if rawAddress.Type() != bitcoin.ScriptTypePKH {
			continue
		}

		hash, _ := rawAddress.Hash()
		if bytes.Equal(pkh, hash.Bytes()) {
			if len(receiver.encryptedKey) == 0 {
				if len(ep.receivers) != 1 {
					// For more than one receiver, an encrypted key must be provided.
					return nil, errors.New("Missing encryption key for receiver")
				}

				// Use DH secret
				secret, err := ecdhSecret(receiverKey, senderPubKey)
				if err != nil {
					return nil, err
				}
				encryptionKey := bitcoin.Sha256(secret)

				return decrypt(ep.payload, encryptionKey)
			} else {
				// Decrypt key using DH key
				secret, err := ecdhSecret(receiverKey, senderPubKey)
				if err != nil {
					return nil, err
				}
				dhKey := bitcoin.Sha256(secret)

				encryptionKey, err := decrypt(receiver.encryptedKey, dhKey)
				if err != nil {
					return nil, err
				}

				return decrypt(ep.payload, encryptionKey)
			}
		}
	}

	return nil, errors.New("Matching receiver not found")
}

// ecdhSecret returns the secret derived using ECDH (Elliptic Curve Diffie Hellman).
func ecdhSecret(k bitcoin.Key, pub bitcoin.PublicKey) ([]byte, error) {
	var x, y big.Int
	pubX, pubY := pub.Numbers()
	x.SetBytes(pubX)
	y.SetBytes(pubY)

	sx, _ := btcec.S256().ScalarMult(&x, &y, k.Number()) // DH is just k * pub
	return sx.Bytes(), nil
}

// encrypt generates a random IV prepends it to the output, then uses AES with the input keysize and
//   CBC to encrypt the payload.
func encrypt(payload, key []byte) ([]byte, error) {
	// Append 0xff to end of payload so padding, for block alignment, can be removed.
	size := len(payload)
	newSize := size + 1
	if newSize%aes.BlockSize != 0 {
		newSize = newSize + (aes.BlockSize - (newSize % aes.BlockSize))
	}
	plaintext := make([]byte, newSize)
	copy(plaintext, payload)
	plaintext[size] = 0xff

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	_, err = rand.Read(ciphertext[:aes.BlockSize]) // IV
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(aesCipher, ciphertext[:aes.BlockSize])
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// TODO Append plaintext hash

	return ciphertext, nil
}

// decrypt reads the IV from the beginning of the output, then uses AES with the input keysize and
//   CBC to decrypt the payload.
func decrypt(payload, key []byte) ([]byte, error) {
	size := len(payload)
	if size == 0 {
		return nil, nil
	}
	if size <= aes.BlockSize {
		return nil, errors.New("Payload too short for decrypt")
	}

	if len(payload)%aes.BlockSize != 0 {
		return nil, errors.New("Payload size doesn't align with decrypt block size")
	}

	// TODO Check plaintext hash

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := payload[:aes.BlockSize]
	ciphertext := payload[aes.BlockSize:]
	plaintext := make([]byte, len(ciphertext))

	mode := cipher.NewCBCDecrypter(aesCipher, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Trim padding by looking for appended 0xff.
	found := false
	stop := 0
	if len(plaintext) > aes.BlockSize {
		stop = len(plaintext) - aes.BlockSize
	}
	payloadLength := 0
	for i := len(plaintext) - 1; ; i-- {
		if plaintext[i] == 0xff {
			found = true
			payloadLength = i
			break
		}
		if i == stop {
			break
		}
	}

	if !found {
		return nil, ErrDecryptInvalid
	}

	return plaintext[:payloadLength], nil
}
