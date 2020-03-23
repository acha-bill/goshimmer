package tipselector

import (
	"testing"
	"time"

	"github.com/iotaledger/hive.go/identity"
	"github.com/stretchr/testify/assert"

	"github.com/iotaledger/goshimmer/packages/binary/tangle/model/message"
	"github.com/iotaledger/goshimmer/packages/binary/tangle/model/message/payload/data"
)

func Test(t *testing.T) {
	// create tip selector
	tipSelector := New()

	// check if first tips point to genesis
	trunk1, branch1 := tipSelector.GetTips()
	assert.Equal(t, message.EmptyId, trunk1)
	assert.Equal(t, message.EmptyId, branch1)

	// create a transaction and attach it
	localIdentity1 := identity.GenerateLocalIdentity()
	transaction1 := message.New(trunk1, branch1, localIdentity1.PublicKey(), time.Now(), 0, data.New([]byte("testtransaction")), localIdentity1)
	tipSelector.AddTip(transaction1)

	// check if the tip shows up in the tip count
	assert.Equal(t, 1, tipSelector.GetTipCount())

	// check if next tips point to our first transaction
	trunk2, branch2 := tipSelector.GetTips()
	assert.Equal(t, transaction1.GetId(), trunk2)
	assert.Equal(t, transaction1.GetId(), branch2)

	// create a 2nd transaction and attach it
	localIdentity2 := identity.GenerateLocalIdentity()
	transaction2 := message.New(message.EmptyId, message.EmptyId, localIdentity2.PublicKey(), time.Now(), 0, data.New([]byte("testtransaction")), localIdentity2)
	tipSelector.AddTip(transaction2)

	// check if the tip shows up in the tip count
	assert.Equal(t, 2, tipSelector.GetTipCount())

	// attach a transaction to our two tips
	localIdentity3 := identity.GenerateLocalIdentity()
	trunk3, branch3 := tipSelector.GetTips()
	transaction3 := message.New(trunk3, branch3, localIdentity3.PublicKey(), time.Now(), 0, data.New([]byte("testtransaction")), localIdentity3)
	tipSelector.AddTip(transaction3)

	// check if the tip shows replaces the current tips
	trunk4, branch4 := tipSelector.GetTips()
	assert.Equal(t, 1, tipSelector.GetTipCount())
	assert.Equal(t, transaction3.GetId(), trunk4)
	assert.Equal(t, transaction3.GetId(), branch4)
}
