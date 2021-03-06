package transactionparser

import (
	"sync"

	"github.com/iotaledger/goshimmer/packages/binary/tangle/model/transaction"
	"github.com/iotaledger/goshimmer/packages/binary/tangle/transactionparser/builtinfilters"

	"github.com/iotaledger/hive.go/events"
	"github.com/iotaledger/hive.go/typeutils"
)

type TransactionParser struct {
	bytesFilters       []BytesFilter
	transactionFilters []TransactionFilter
	Events             transactionParserEvents

	byteFiltersModified        typeutils.AtomicBool
	transactionFiltersModified typeutils.AtomicBool
	bytesFiltersMutex          sync.Mutex
	transactionFiltersMutex    sync.Mutex
}

func New() (result *TransactionParser) {
	result = &TransactionParser{
		bytesFilters:       make([]BytesFilter, 0),
		transactionFilters: make([]TransactionFilter, 0),

		Events: transactionParserEvents{
			BytesRejected: events.NewEvent(func(handler interface{}, params ...interface{}) {
				handler.(func([]byte))(params[0].([]byte))
			}),
			TransactionParsed: events.NewEvent(func(handler interface{}, params ...interface{}) {
				handler.(func(*transaction.Transaction))(params[0].(*transaction.Transaction))
			}),
			TransactionRejected: events.NewEvent(func(handler interface{}, params ...interface{}) {
				handler.(func(*transaction.Transaction))(params[0].(*transaction.Transaction))
			}),
		},
	}

	// add builtin filters
	result.AddBytesFilter(builtinfilters.NewRecentlySeenBytesFilter())
	result.AddTransactionsFilter(builtinfilters.NewTransactionSignatureFilter())

	return
}

func (transactionParser *TransactionParser) Parse(transactionBytes []byte) {
	transactionParser.setupBytesFilterDataFlow()
	transactionParser.setupTransactionsFilterDataFlow()

	transactionParser.bytesFilters[0].Filter(transactionBytes)
}

func (transactionParser *TransactionParser) AddBytesFilter(filter BytesFilter) {
	transactionParser.bytesFiltersMutex.Lock()
	transactionParser.bytesFilters = append(transactionParser.bytesFilters, filter)
	transactionParser.bytesFiltersMutex.Unlock()

	transactionParser.byteFiltersModified.Set()
}

func (transactionParser *TransactionParser) AddTransactionsFilter(filter TransactionFilter) {
	transactionParser.transactionFiltersMutex.Lock()
	transactionParser.transactionFilters = append(transactionParser.transactionFilters, filter)
	transactionParser.transactionFiltersMutex.Unlock()

	transactionParser.transactionFiltersModified.Set()
}

func (transactionParser *TransactionParser) Shutdown() {
	transactionParser.bytesFiltersMutex.Lock()
	for _, bytesFilter := range transactionParser.bytesFilters {
		bytesFilter.Shutdown()
	}
	transactionParser.bytesFiltersMutex.Unlock()

	transactionParser.transactionFiltersMutex.Lock()
	for _, transactionFilter := range transactionParser.transactionFilters {
		transactionFilter.Shutdown()
	}
	transactionParser.transactionFiltersMutex.Unlock()
}

func (transactionParser *TransactionParser) setupBytesFilterDataFlow() {
	if !transactionParser.byteFiltersModified.IsSet() {
		return
	}

	transactionParser.bytesFiltersMutex.Lock()
	if transactionParser.byteFiltersModified.IsSet() {
		transactionParser.byteFiltersModified.SetTo(false)

		numberOfBytesFilters := len(transactionParser.bytesFilters)
		for i := 0; i < numberOfBytesFilters; i++ {
			if i == numberOfBytesFilters-1 {
				transactionParser.bytesFilters[i].OnAccept(transactionParser.parseTransaction)
			} else {
				transactionParser.bytesFilters[i].OnAccept(transactionParser.bytesFilters[i+1].Filter)
			}
			transactionParser.bytesFilters[i].OnReject(func(bytes []byte) { transactionParser.Events.BytesRejected.Trigger(bytes) })
		}
	}
	transactionParser.bytesFiltersMutex.Unlock()
}

func (transactionParser *TransactionParser) setupTransactionsFilterDataFlow() {
	if !transactionParser.transactionFiltersModified.IsSet() {
		return
	}

	transactionParser.transactionFiltersMutex.Lock()
	if transactionParser.transactionFiltersModified.IsSet() {
		transactionParser.transactionFiltersModified.SetTo(false)

		numberOfTransactionFilters := len(transactionParser.transactionFilters)
		for i := 0; i < numberOfTransactionFilters; i++ {
			if i == numberOfTransactionFilters-1 {
				transactionParser.transactionFilters[i].OnAccept(func(tx *transaction.Transaction) { transactionParser.Events.TransactionParsed.Trigger(tx) })
			} else {
				transactionParser.transactionFilters[i].OnAccept(transactionParser.transactionFilters[i+1].Filter)
			}
			transactionParser.transactionFilters[i].OnReject(func(tx *transaction.Transaction) { transactionParser.Events.TransactionRejected.Trigger(tx) })
		}
	}
	transactionParser.transactionFiltersMutex.Unlock()
}

func (transactionParser *TransactionParser) parseTransaction(bytes []byte) {
	if parsedTransaction, err := transaction.FromBytes(bytes); err != nil {
		// trigger parsingError
		panic(err)
	} else {
		transactionParser.transactionFilters[0].Filter(parsedTransaction)
	}
}
