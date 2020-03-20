package transactionmetadata

import (
	"github.com/iotaledger/hive.go/objectstorage"
)

type CachedTransactionMetadata struct {
	objectstorage.CachedObject
}

func (cachedObject *CachedTransactionMetadata) Retain() *CachedTransactionMetadata {
	return &CachedTransactionMetadata{cachedObject.CachedObject.Retain()}
}

func (cachedObject *CachedTransactionMetadata) Unwrap() *TransactionMetadata {
	if untypedObject := cachedObject.Get(); untypedObject == nil {
		return nil
	} else {
		if typedObject := untypedObject.(*TransactionMetadata); typedObject == nil || typedObject.IsDeleted() {
			return nil
		} else {
			return typedObject
		}
	}
}
