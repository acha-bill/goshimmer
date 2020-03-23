package transactionparser

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/iotaledger/hive.go/events"
	"github.com/iotaledger/hive.go/identity"

	"github.com/iotaledger/goshimmer/packages/binary/tangle/model/message"
	"github.com/iotaledger/goshimmer/packages/binary/tangle/model/message/payload/data"
)

func BenchmarkTransactionParser_ParseBytesSame(b *testing.B) {
	localIdentity := identity.GenerateLocalIdentity()
	txBytes := message.New(message.EmptyId, message.EmptyId, localIdentity.PublicKey(), time.Now(), 0, data.New([]byte("Test")), localIdentity).Bytes()
	txParser := New()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		txParser.Parse(txBytes, nil)
	}

	txParser.Shutdown()
}

func BenchmarkTransactionParser_ParseBytesDifferent(b *testing.B) {
	transactionBytes := make([][]byte, b.N)
	localIdentity := identity.GenerateLocalIdentity()
	for i := 0; i < b.N; i++ {
		transactionBytes[i] = message.New(message.EmptyId, message.EmptyId, localIdentity.PublicKey(), time.Now(), 0, data.New([]byte("Test"+strconv.Itoa(i))), localIdentity).Bytes()
	}

	txParser := New()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		txParser.Parse(transactionBytes[i], nil)
	}

	txParser.Shutdown()
}

func TestTransactionParser_ParseTransaction(t *testing.T) {
	localIdentity := identity.GenerateLocalIdentity()
	tx := message.New(message.EmptyId, message.EmptyId, localIdentity.PublicKey(), time.Now(), 0, data.New([]byte("Test")), localIdentity)

	txParser := New()
	txParser.Parse(tx.Bytes(), nil)

	txParser.Events.TransactionParsed.Attach(events.NewClosure(func(tx *message.Transaction) {
		fmt.Println("PARSED!!!")
	}))

	txParser.Shutdown()
}
