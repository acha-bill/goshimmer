package spammer

import (
	"sync/atomic"
	"time"

	"github.com/iotaledger/hive.go/types"

	"github.com/iotaledger/goshimmer/packages/binary/messagelayer/model/message"
	"github.com/iotaledger/goshimmer/packages/binary/messagelayer/model/message/payload/data"
	"github.com/iotaledger/goshimmer/packages/binary/messagelayer/tipselector"
	"github.com/iotaledger/goshimmer/packages/binary/messagelayer/transactionparser"
	"github.com/iotaledger/goshimmer/packages/binary/signature/ed25119"
)

type Spammer struct {
	transactionParser *transactionparser.TransactionParser
	tipSelector       *tipselector.TipSelector

	processId      int64
	shutdownSignal chan types.Empty
}

func New(transactionParser *transactionparser.TransactionParser, tipSelector *tipselector.TipSelector) *Spammer {
	return &Spammer{
		shutdownSignal:    make(chan types.Empty),
		transactionParser: transactionParser,
		tipSelector:       tipSelector,
	}
}

func (spammer *Spammer) Start(tps int) {
	go spammer.run(tps, atomic.AddInt64(&spammer.processId, 1))
}

func (spammer *Spammer) Burst(transactions int) {
	go spammer.sendBurst(transactions, atomic.AddInt64(&spammer.processId, 1))
}

func (spammer *Spammer) Shutdown() {
	atomic.AddInt64(&spammer.processId, 1)
}

func (spammer *Spammer) run(tps int, processId int64) {
	spammingIdentity := ed25119.GenerateKeyPair()
	currentSentCounter := 0
	start := time.Now()

	for {
		if atomic.LoadInt64(&spammer.processId) != processId {
			return
		}

		trunkTransactionId, branchTransactionId := spammer.tipSelector.GetTips()
		spammer.transactionParser.Parse(
			message.New(trunkTransactionId, branchTransactionId, spammingIdentity, time.Now(), 0, data.NewData([]byte("SPAM"))).Bytes(),
			nil,
		)

		currentSentCounter++

		// rate limit to the specified TPS
		if currentSentCounter >= tps {
			duration := time.Since(start)
			if duration < time.Second {
				time.Sleep(time.Second - duration)
			}

			start = time.Now()
			currentSentCounter = 0
		}
	}
}

func (spammer *Spammer) sendBurst(transactions int, processId int64) {
	spammingIdentity := ed25119.GenerateKeyPair()

	previousTransactionId := message.EmptyId

	burstBuffer := make([][]byte, transactions)
	for i := 0; i < transactions; i++ {
		if atomic.LoadInt64(&spammer.processId) != processId {
			return
		}

		spamTransaction := message.New(previousTransactionId, previousTransactionId, spammingIdentity, time.Now(), 0, data.NewData([]byte("SPAM")))
		previousTransactionId = spamTransaction.GetId()
		burstBuffer[i] = spamTransaction.Bytes()
	}

	for i := 0; i < transactions; i++ {
		if atomic.LoadInt64(&spammer.processId) != processId {
			return
		}

		spammer.transactionParser.Parse(burstBuffer[i], nil)
	}
}
