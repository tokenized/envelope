package version_0

import (
	"github.com/pkg/errors"
	"github.com/tokenized/smart-contract/pkg/bitcoin"
	"github.com/tokenized/smart-contract/pkg/wire"
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
	if mn.publicKey != nil {
		return mn.publicKey, nil
	}

	if int(mn.index) >= len(tx.TxIn) {
		return nil, errors.New("Index out of range")
	}

	pubKey, err := bitcoin.PublicKeyFromUnlockingScript(tx.TxIn[mn.index].SignatureScript)
	if err != nil {
		return nil, err
	}

	mn.publicKey, err = bitcoin.DecodePublicKeyBytes(pubKey)
	if err != nil {
		return nil, err
	}

	return mn.publicKey, nil
}

func (mn *MetaNet) Parent() []byte {
	return mn.parent
}
