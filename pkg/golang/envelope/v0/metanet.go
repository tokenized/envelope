package v0

import (
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"

	"github.com/pkg/errors"
)

type MetaNet struct {
	index     uint32
	publicKey bitcoin.PublicKey
	parent    []byte
}

func NewMetaNet(index uint32, publicKey bitcoin.PublicKey, parent []byte) *MetaNet {
	return &MetaNet{
		index:     index,
		publicKey: publicKey,
		parent:    parent,
	}
}

func (mn *MetaNet) Index() uint32 {
	return mn.index
}

func (mn *MetaNet) PublicKey(tx *wire.MsgTx) (bitcoin.PublicKey, error) {
	if mn.publicKey.IsEmpty() {
		return mn.publicKey, nil
	}

	if int(mn.index) >= len(tx.TxIn) {
		return bitcoin.PublicKey{}, errors.New("Index out of range")
	}

	pubKey, err := bitcoin.PublicKeyFromUnlockingScript(tx.TxIn[mn.index].SignatureScript)
	if err != nil {
		return bitcoin.PublicKey{}, err
	}

	mn.publicKey, err = bitcoin.PublicKeyFromBytes(pubKey)
	if err != nil {
		return bitcoin.PublicKey{}, err
	}

	return mn.publicKey, nil
}

func (mn *MetaNet) Parent() []byte {
	return mn.parent
}
