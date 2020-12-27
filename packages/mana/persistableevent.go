package mana

import (
	"crypto/sha256"
	"math"
	"time"

	"github.com/iotaledger/goshimmer/dapps/valuetransfers/packages/transaction"
	"github.com/iotaledger/hive.go/identity"
	"github.com/iotaledger/hive.go/marshalutil"
	"github.com/iotaledger/hive.go/objectstorage"
)

// PersistableEvent is a persistable pledge event.
type PersistableEvent struct {
	objectstorage.StorableObjectFlags
	Type          byte // pledge or revoke
	NodeID        identity.ID
	Amount        float64
	Time          time.Time
	ManaType      Type // access or consensus
	TransactionID transaction.ID
	bytes         []byte
}

// Bytes marshals the persistable event into a sequence of bytes.
func (p *PersistableEvent) Bytes() []byte {
	if bytes := p.bytes; bytes != nil {
		return bytes
	}
	// create marshal helper
	marshalUtil := marshalutil.New()
	marshalUtil.WriteByte(p.Type)
	marshalUtil.WriteInt64(int64(p.ManaType))
	marshalUtil.WriteBytes(p.NodeID.Bytes())
	marshalUtil.WriteTime(p.Time)
	marshalUtil.WriteBytes(p.TransactionID.Bytes())
	marshalUtil.WriteUint64(math.Float64bits(p.Amount))
	p.bytes = marshalUtil.Bytes()
	return p.bytes
}

// Update updates the event in storage.
func (p *PersistableEvent) Update(objectstorage.StorableObject) {
	panic("should not be updated")
}

// ObjectStorageKey returns the key of the persistable mana.
func (p *PersistableEvent) ObjectStorageKey() []byte {
	return []byte(p.TransactionID.String() + p.Time.String() + p.NodeID.String())
}

// ObjectStorageValue returns the bytes of the event.
func (p *PersistableEvent) ObjectStorageValue() []byte {
	return p.Bytes()
}

// parseEvent unmarshals a PersistableEvent using the given marshalUtil (for easier marshaling/unmarshaling).
func parseEvent(marshalUtil *marshalutil.MarshalUtil) (result *PersistableEvent, err error) {
	eventType, err := marshalUtil.ReadByte()
	if err != nil {
		return
	}
	manaType, err := marshalUtil.ReadInt64()
	if err != nil {
		return
	}
	nodeIDBytes, err := marshalUtil.ReadBytes(sha256.Size)
	if err != nil {
		return
	}
	nodeID := identity.ID{}
	copy(nodeID[:], nodeIDBytes)

	eventTime, err := marshalUtil.ReadTime()
	if err != nil {
		return
	}
	txIDBytes, err := marshalUtil.ReadBytes(transaction.IDLength)
	if err != nil {
		return
	}
	txID := transaction.ID{}
	copy(txID[:], txIDBytes)

	_amount, err := marshalUtil.ReadUint64()
	if err != nil {
		return
	}
	amount := math.Float64frombits(_amount)
	consumedBytes := marshalUtil.ReadOffset()

	result = &PersistableEvent{
		Type:          eventType,
		NodeID:        nodeID,
		Amount:        amount,
		Time:          eventTime,
		ManaType:      Type(manaType),
		TransactionID: txID,
	}
	result.bytes = make([]byte, consumedBytes)
	copy(result.bytes, marshalUtil.Bytes())
	return
}

// FromEventObjectStorage unmarshalls bytes into a persistable event.
func FromEventObjectStorage(_ []byte, data []byte) (result objectstorage.StorableObject, err error) {
	return parseEvent(marshalutil.New(data))
}

// CachedPersistableEvent represents cached persistable event.
type CachedPersistableEvent struct {
	objectstorage.CachedObject
}

// Retain marks this CachedObject to still be in use by the program.
func (c *CachedPersistableEvent) Retain() *CachedPersistableEvent {
	return &CachedPersistableEvent{c.CachedObject.Retain()}
}

// Consume unwraps the CachedObject and passes a type-casted version to the consumer (if the object is not empty - it
// exists). It automatically releases the object when the consumer finishes.
func (c *CachedPersistableEvent) Consume(consumer func(pbm *PersistableEvent)) bool {
	return c.CachedObject.Consume(func(object objectstorage.StorableObject) {
		consumer(object.(*PersistableEvent))
	})
}

// Unwrap is the type-casted equivalent of Get. It returns nil if the object does not exist.
func (c *CachedPersistableEvent) Unwrap() *PersistableEvent {
	untypedPbm := c.Get()
	if untypedPbm == nil {
		return nil
	}

	typeCastedPbm := untypedPbm.(*PersistableEvent)
	if typeCastedPbm == nil || typeCastedPbm.IsDeleted() {
		return nil
	}

	return typeCastedPbm
}

var _ objectstorage.StorableObject = &PersistableEvent{}