package ledgerstate

import (
	"sync"
	"sync/atomic"

	"github.com/iotaledger/goshimmer/packages/binary/address"

	"github.com/iotaledger/goshimmer/packages/stringify"

	"github.com/iotaledger/goshimmer/packages/errors"
	"github.com/iotaledger/hive.go/objectstorage"
)

type Reality struct {
	objectstorage.StorableObjectFlags

	id                    RealityId
	parentRealityIds      RealityIdSet
	parentRealityIdsMutex sync.RWMutex
	subRealityIds         RealityIdSet
	subRealityIdsMutex    sync.RWMutex
	conflictIds           ConflictIdSet
	conflictIdsMutex      sync.RWMutex
	transferOutputCount   uint32
	preferred             bool
	preferredMutex        sync.RWMutex
	liked                 bool
	likedMutex            sync.RWMutex

	storageKey  []byte
	ledgerState *LedgerState
}

func (reality *Reality) areParentsLiked() (parentsLiked bool) {
	parentsLiked = true
	for _, cachedParentReality := range reality.GetParentRealities() {
		if parentsLiked {
			cachedParentReality.Consume(func(object objectstorage.StorableObject) {
				parentsLiked = parentsLiked && object.(*Reality).IsLiked()
			})
		} else {
			cachedParentReality.Release()
		}
	}

	return
}

func (reality *Reality) propagateLiked() {
	reality.likedMutex.Lock()
	reality.liked = true
	reality.likedMutex.Unlock()

	reality.SetModified()

	for _, cachedSubReality := range reality.GetSubRealities() {
		if !cachedSubReality.Exists() {
			cachedSubReality.Release()

			// TODO: SWITCH TO ERR INSTEAD OF PANIC
			panic("could not load sub reality")
		}

		cachedSubReality.Consume(func(object objectstorage.StorableObject) {
			subReality := object.(*Reality)

			subReality.parentRealityIdsMutex.RLock()
			if len(subReality.parentRealityIds) == 1 && subReality.parentRealityIds.Contains(reality.id) {
				subReality.parentRealityIdsMutex.RUnlock()

				subReality.propagateLiked()
			} else {
				subReality.parentRealityIdsMutex.RUnlock()

				if subReality.areParentsLiked() {
					subReality.propagateLiked()
				}
			}
		})
	}
}

func (reality *Reality) propagateDisliked() {
	reality.likedMutex.Lock()
	reality.liked = false
	reality.likedMutex.Unlock()

	reality.SetModified()

	for _, cachedSubReality := range reality.GetSubRealities() {
		if !cachedSubReality.Exists() {
			cachedSubReality.Release()

			// TODO: SWITCH TO ERR INSTEAD OF PANIC
			panic("could not load sub reality")
		}

		cachedSubReality.Consume(func(object objectstorage.StorableObject) {
			subReality := object.(*Reality)

			if subReality.IsLiked() {
				subReality.propagateDisliked()
			}
		})
	}
}

func (reality *Reality) GetSubRealities() (subRealities objectstorage.CachedObjects) {
	reality.subRealityIdsMutex.RLock()
	subRealities = make(objectstorage.CachedObjects, len(reality.subRealityIds))
	i := 0
	for subRealityId := range reality.subRealityIds {
		subRealities[i] = reality.ledgerState.GetReality(subRealityId)

		i++
	}
	reality.subRealityIdsMutex.RUnlock()

	return
}

func (reality *Reality) SetPreferred(preferred ...bool) (updated bool) {
	newPreferredValue := len(preferred) == 0 || preferred[0]

	reality.preferredMutex.RLock()
	if reality.preferred != newPreferredValue {
		reality.preferredMutex.RUnlock()

		reality.preferredMutex.Lock()
		if reality.preferred != newPreferredValue {
			reality.preferred = newPreferredValue

			if newPreferredValue {
				if reality.areParentsLiked() {
					reality.propagateLiked()
				}
			} else {
				if reality.IsLiked() {
					reality.propagateDisliked()
				}
			}

			updated = true

			reality.SetModified()
		}
		reality.preferredMutex.Unlock()
	} else {
		reality.preferredMutex.RUnlock()
	}

	return
}

func (reality *Reality) IsPreferred() (preferred bool) {
	reality.preferredMutex.RLock()
	preferred = reality.preferred
	reality.preferredMutex.RUnlock()

	return
}

// region DONE REVIEWING ///////////////////////////////////////////////////////////////////////////////////////////////

// Creates a new Reality with the given id and parents. It is only used internally and therefore "private".
func newReality(id RealityId, parentRealities ...RealityId) *Reality {
	result := &Reality{
		id:               id,
		parentRealityIds: NewRealityIdSet(parentRealities...),
		subRealityIds:    NewRealityIdSet(),
		conflictIds:      NewConflictIdSet(),

		storageKey: make([]byte, len(id)),
	}
	copy(result.storageKey, id[:])

	return result
}

func (reality *Reality) IsLiked() (liked bool) {
	reality.likedMutex.RLock()
	liked = reality.liked
	reality.likedMutex.RUnlock()

	return
}

func (reality *Reality) SetLiked(liked ...bool) (likedStatusChanged bool) {
	newLikedStatus := len(liked) == 0 || liked[0]

	reality.likedMutex.RLock()
	if reality.liked != newLikedStatus {
		reality.likedMutex.RUnlock()

		reality.likedMutex.Lock()
		if reality.liked != newLikedStatus {
			reality.liked = newLikedStatus

			likedStatusChanged = true

			reality.SetModified()
		}
		reality.likedMutex.Unlock()
	} else {
		reality.likedMutex.RUnlock()
	}

	return
}

// Returns the id of this Reality. Since the id never changes, we do not need a mutex to protect this property.
func (reality *Reality) GetId() RealityId {
	return reality.id
}

// Returns the set of RealityIds that are the parents of this Reality (it creates a clone).
func (reality *Reality) GetParentRealityIds() (realityIdSet RealityIdSet) {
	reality.parentRealityIdsMutex.RLock()
	realityIdSet = reality.parentRealityIds.Clone()
	reality.parentRealityIdsMutex.RUnlock()

	return
}

// Adds a new parent Reality to this Reality (it is used for aggregating aggregated Realities).
func (reality *Reality) AddParentReality(realityId RealityId) (realityAdded bool) {
	reality.parentRealityIdsMutex.RLock()
	if _, exists := reality.parentRealityIds[realityId]; !exists {
		reality.parentRealityIdsMutex.RUnlock()

		reality.parentRealityIdsMutex.Lock()
		if _, exists := reality.parentRealityIds[realityId]; !exists {
			reality.parentRealityIds[realityId] = void

			reality.SetModified()

			realityAdded = true
		}
		reality.parentRealityIdsMutex.Unlock()
	} else {
		reality.parentRealityIdsMutex.RUnlock()
	}

	return
}

// Utility function that replaces the parent of a reality.
// Since IO is the most expensive part of the ledger state, we only update the parents and mark the reality as modified
// if either the oldRealityId exists or the newRealityId does not exist.
func (reality *Reality) replaceParentReality(oldRealityId RealityId, newRealityId RealityId) {
	reality.parentRealityIdsMutex.RLock()
	if _, oldRealityIdExist := reality.parentRealityIds[oldRealityId]; oldRealityIdExist {
		reality.parentRealityIdsMutex.RUnlock()

		reality.parentRealityIdsMutex.Lock()
		if _, oldRealityIdExist := reality.parentRealityIds[oldRealityId]; oldRealityIdExist {
			delete(reality.parentRealityIds, oldRealityId)

			if _, newRealityIdExist := reality.parentRealityIds[newRealityId]; !newRealityIdExist {
				reality.parentRealityIds[newRealityId] = void
			}

			reality.SetModified()
		} else {
			if _, newRealityIdExist := reality.parentRealityIds[newRealityId]; !newRealityIdExist {
				reality.parentRealityIds[newRealityId] = void

				reality.SetModified()
			}
		}
		reality.parentRealityIdsMutex.Unlock()
	} else {
		if _, newRealityIdExist := reality.parentRealityIds[newRealityId]; !newRealityIdExist {
			reality.parentRealityIdsMutex.RUnlock()

			reality.parentRealityIdsMutex.Lock()
			if _, newRealityIdExist := reality.parentRealityIds[newRealityId]; !newRealityIdExist {
				reality.parentRealityIds[newRealityId] = void

				reality.SetModified()
			}
			reality.parentRealityIdsMutex.Unlock()
		} else {
			reality.parentRealityIdsMutex.RUnlock()
		}
	}
}

// Returns the amount of TransferOutputs in this Reality.
func (reality *Reality) GetTransferOutputCount() uint32 {
	return atomic.LoadUint32(&(reality.transferOutputCount))
}

// Increases (and returns) the amount of TransferOutputs in this Reality.
func (reality *Reality) IncreaseTransferOutputCount() (transferOutputCount uint32) {
	transferOutputCount = atomic.AddUint32(&(reality.transferOutputCount), 1)

	reality.SetModified()

	return
}

// Decreases (and returns) the amount of TransferOutputs in this Reality.
func (reality *Reality) DecreaseTransferOutputCount() (transferOutputCount uint32) {
	transferOutputCount = atomic.AddUint32(&(reality.transferOutputCount), ^uint32(0))

	reality.SetModified()

	return
}

// Returns true, if this reality is an "aggregated reality" that combines multiple other realities.
func (reality *Reality) IsAggregated() (isAggregated bool) {
	reality.parentRealityIdsMutex.RLock()
	isAggregated = len(reality.parentRealityIds) > 1
	reality.parentRealityIdsMutex.RUnlock()

	return
}

// Returns true if the given RealityId addresses the Reality itself or one of its ancestors.
func (reality *Reality) DescendsFrom(realityId RealityId) bool {
	if reality.id == realityId {
		return true
	} else {
		descendsFromReality := false

		for ancestorRealityId, ancestorReality := range reality.GetAncestorRealities() {
			if ancestorRealityId == realityId {
				descendsFromReality = true
			}

			ancestorReality.Release()
		}

		return descendsFromReality
	}
}

// Returns a map of all parent realities (one level). They have to be "released" manually when they are not needed
// anymore.
func (reality *Reality) GetParentRealities() (parentRealities map[RealityId]*objectstorage.CachedObject) {
	parentRealities = make(map[RealityId]*objectstorage.CachedObject)

	reality.parentRealityIdsMutex.RLock()
	for parentRealityId := range reality.parentRealityIds {
		loadedParentReality := reality.ledgerState.GetReality(parentRealityId)
		if !loadedParentReality.Exists() {
			reality.parentRealityIdsMutex.RUnlock()

			panic("could not load parent reality with id \"" + string(parentRealityId[:]) + "\"")
		}

		parentRealities[loadedParentReality.Get().(*Reality).id] = loadedParentReality
	}
	reality.parentRealityIdsMutex.RUnlock()

	return
}

// Returns a map of all parent realities that are not aggregated (aggregated realities are "transparent"). They have to
// be "released" manually when they are not needed anymore.
func (reality *Reality) GetParentConflictRealities() map[RealityId]*objectstorage.CachedObject {
	if !reality.IsAggregated() {
		return reality.GetParentRealities()
	} else {
		parentConflictRealities := make(map[RealityId]*objectstorage.CachedObject)

		reality.collectParentConflictRealities(parentConflictRealities)

		return parentConflictRealities
	}
}

// Returns a map of all ancestor realities (up till the MAIN_REALITY). They have to manually be "released" when they are
// not needed anymore.
func (reality *Reality) GetAncestorRealities() (result map[RealityId]*objectstorage.CachedObject) {
	result = make(map[RealityId]*objectstorage.CachedObject, 1)

	for parentRealityId, parentReality := range reality.GetParentRealities() {
		result[parentRealityId] = parentReality

		for ancestorId, ancestor := range parentReality.Get().(*Reality).GetAncestorRealities() {
			result[ancestorId] = ancestor
		}
	}

	return
}

// Registers the conflict set in the Reality.
func (reality *Reality) AddConflict(conflictSetId ConflictId) {
	reality.conflictIdsMutex.RLock()
	if _, exists := reality.conflictIds[conflictSetId]; !exists {
		reality.conflictIdsMutex.RUnlock()

		reality.conflictIdsMutex.Lock()
		if _, exists := reality.conflictIds[conflictSetId]; !exists {
			reality.conflictIds[conflictSetId] = void

			reality.SetModified()
		}
		reality.conflictIdsMutex.Unlock()
	} else {
		reality.conflictIdsMutex.RUnlock()
	}
}

// Creates a new sub Reality and "stores" it. It has to manually be "released" when it is not needed anymore.
func (reality *Reality) CreateReality(id RealityId) *objectstorage.CachedObject {
	newReality := newReality(id, reality.id)
	newReality.ledgerState = reality.ledgerState

	reality.RegisterSubReality(id)

	return reality.ledgerState.realities.Store(newReality)
}

// Books a transfer into this reality (wrapper for the private bookTransfer function).
func (reality *Reality) BookTransfer(transfer *Transfer) (err error) {
	err = reality.bookTransfer(transfer.GetHash(), reality.ledgerState.getTransferInputs(transfer), transfer.GetOutputs())

	return
}

// Creates a string representation of this Reality.
func (reality *Reality) String() (result string) {
	reality.parentRealityIdsMutex.RLock()
	parentRealities := make([]string, len(reality.parentRealityIds))
	i := 0
	for parentRealityId := range reality.parentRealityIds {
		parentRealities[i] = parentRealityId.String()

		i++
	}
	reality.parentRealityIdsMutex.RUnlock()

	result = stringify.Struct("Reality",
		stringify.StructField("id", reality.GetId().String()),
		stringify.StructField("parentRealities", parentRealities),
	)

	return
}

// Books a transfer into this reality (contains the dispatcher for the actual tasks).
func (reality *Reality) bookTransfer(transferHash TransferHash, inputs objectstorage.CachedObjects, outputs map[address.Address][]*ColoredBalance) (err error) {
	if err = reality.verifyTransfer(inputs, outputs); err != nil {
		return
	}

	conflicts, err := reality.consumeInputs(inputs, transferHash, outputs)
	if err != nil {
		return
	}

	if err = reality.createTransferOutputs(transferHash, outputs, conflicts); err != nil {
		return
	}

	conflicts.Release()
	inputs.Release()

	return
}

// Internal utility function that verifies the transfer and checks if it is valid (inputs exist + the net balance is 0).
func (reality *Reality) verifyTransfer(inputs []*objectstorage.CachedObject, outputs map[address.Address][]*ColoredBalance) error {
	totalColoredBalances := make(map[Color]uint64)

	for _, cachedInput := range inputs {
		if !cachedInput.Exists() {
			return errors.New("missing input in transfer")
		}

		input := cachedInput.Get().(*TransferOutput)
		if !reality.DescendsFrom(input.GetRealityId()) {
			return errors.New("the referenced funds do not exist in this reality")
		}

		for _, balance := range input.GetBalances() {
			totalColoredBalances[balance.GetColor()] += balance.GetValue()
		}
	}

	for _, transferOutput := range outputs {
		for _, balance := range transferOutput {
			color := balance.GetColor()

			totalColoredBalances[color] -= balance.GetValue()

			if totalColoredBalances[color] == 0 {
				delete(totalColoredBalances, color)
			}
		}
	}

	// transfer is valid if sum of funds is 0
	if len(totalColoredBalances) != 0 {
		return errors.New("the sum of the balance changes is not 0")
	}

	return nil
}

// Internal utility function that marks the consumed inputs as spent and returns the corresponding conflicts if the
// inputs have been consumed before.
func (reality *Reality) consumeInputs(inputs objectstorage.CachedObjects, transferHash TransferHash, outputs map[address.Address][]*ColoredBalance) (conflicts objectstorage.CachedObjects, err error) {
	conflicts = make(objectstorage.CachedObjects, 0)

	for _, input := range inputs {
		consumedInput := input.Get().(*TransferOutput)

		if consumersToElevate, consumeErr := consumedInput.addConsumer(transferHash, outputs); consumeErr != nil {
			err = consumeErr

			return
		} else if consumersToElevate != nil {
			if conflict, conflictErr := reality.processConflictingInput(consumedInput, consumersToElevate); conflictErr != nil {
				err = conflictErr

				return
			} else {
				conflicts = append(conflicts, conflict)
			}
		}
	}

	return
}

// Private utility function that creates the transfer outputs in the ledger.
//
// If the inputs have been used before and we consequently have a non-empty list of conflicts, we first create a new
// reality for the inputs and then book the transfer outputs into the correct reality.
func (reality *Reality) createTransferOutputs(transferHash TransferHash, outputs map[address.Address][]*ColoredBalance, conflicts objectstorage.CachedObjects) (err error) {
	if len(conflicts) >= 1 {
		targetRealityId := transferHash.ToRealityId()

		reality.CreateReality(targetRealityId).Consume(func(object objectstorage.StorableObject) {
			targetReality := object.(*Reality)

			for _, cachedConflictSet := range conflicts {
				conflictSet := cachedConflictSet.Get().(*Conflict)

				conflictSet.AddReality(targetRealityId)
				targetReality.AddConflict(conflictSet.GetId())
			}

			for addressHash, coloredBalances := range outputs {
				if err = targetReality.bookTransferOutput(NewTransferOutput(reality.ledgerState, emptyRealityId, transferHash, addressHash, coloredBalances...)); err != nil {
					return
				}
			}
		})
	} else {
		for addressHash, coloredBalances := range outputs {
			if err = reality.bookTransferOutput(NewTransferOutput(reality.ledgerState, emptyRealityId, transferHash, addressHash, coloredBalances...)); err != nil {
				return
			}
		}
	}

	return
}

// Utility function that collects all non-aggregated parent realities. It is used by GetParentConflictRealities and
// prevents us from having to allocate multiple maps during recursion.
func (reality *Reality) collectParentConflictRealities(parentConflictRealities map[RealityId]*objectstorage.CachedObject) {
	for realityId, cachedParentReality := range reality.GetParentRealities() {
		parentReality := cachedParentReality.Get().(*Reality)

		if !parentReality.IsAggregated() {
			parentConflictRealities[realityId] = cachedParentReality
		} else {
			parentReality.collectParentConflictRealities(parentConflictRealities)

			cachedParentReality.Release()
		}
	}
}

// Utility function that processes a conflicting input by retrieving the corresponding conflict.
// If there is a non-empty list of consumers to elevate, we elevate them.
func (reality *Reality) processConflictingInput(input *TransferOutput, consumersToElevate map[TransferHash][]address.Address) (conflict *objectstorage.CachedObject, err error) {
	conflictId := NewConflictId(input.GetTransferHash(), input.GetAddressHash())

	if len(consumersToElevate) >= 1 {
		newConflict := newConflictSet(conflictId)
		newConflict.ledgerState = reality.ledgerState

		conflict = reality.ledgerState.conflictSets.Store(newConflict)

		err = reality.createRealityForPreviouslyUnconflictingConsumers(consumersToElevate, conflict.Get().(*Conflict))
	} else {
		if conflict, err = reality.ledgerState.conflictSets.Load(conflictId[:]); err != nil {
			return
		} else {
			conflict.Get().(*Conflict).ledgerState = reality.ledgerState
		}
	}

	return
}

// Creates a Reality for the consumers of the conflicting inputs and registers it as part of the corresponding Conflict.
func (reality *Reality) createRealityForPreviouslyUnconflictingConsumers(consumersOfConflictingInput map[TransferHash][]address.Address, conflict *Conflict) (err error) {
	for transferHash, addressHashes := range consumersOfConflictingInput {
		elevatedRealityId := transferHash.ToRealityId()

		// Retrieve the Reality for this Transfer or create one if no Reality exists, yet.
		var realityIsNew bool
		if cachedElevatedReality, realityErr := reality.ledgerState.realities.ComputeIfAbsent(elevatedRealityId[:], func(key []byte) (object objectstorage.StorableObject, e error) {
			newReality := newReality(elevatedRealityId, reality.id)
			newReality.ledgerState = reality.ledgerState
			newReality.SetPreferred()

			reality.RegisterSubReality(elevatedRealityId)

			newReality.Persist()
			newReality.SetModified()

			realityIsNew = true

			return newReality, nil
		}); realityErr != nil {
			err = realityErr
		} else {
			cachedElevatedReality.Consume(func(object objectstorage.StorableObject) {
				elevatedReality := object.(*Reality)

				// We register every Conflict with the Reality (independent if it is "new" or not), to reflect its
				// association to all corresponding Conflicts. (Note: A Reality can be part of multiple Conflicts if the
				// Transfer that is associated to this Reality consumes multiple inputs.
				conflict.AddReality(elevatedRealityId)
				elevatedReality.AddConflict(conflict.GetId())

				// A transaction can consume multiple inputs. We only elevate the consumers of a Reality once (when the
				// Reality is created the first time).
				if realityIsNew {
					for _, addressHash := range addressHashes {
						if err = reality.elevateTransferOutput(NewTransferOutputReference(transferHash, addressHash), elevatedReality); err != nil {
							return
						}
					}
				}
			})
		}
	}

	return
}

// Private utility function that elevates a transfer output to the given reality.
func (reality *Reality) elevateTransferOutput(transferOutputReference *TransferOutputReference, newReality *Reality) (err error) {
	if cachedTransferOutputToElevate := reality.ledgerState.GetTransferOutput(transferOutputReference); !cachedTransferOutputToElevate.Exists() {
		err = errors.New("could not find TransferOutput to elevate")
	} else {
		cachedTransferOutputToElevate.Consume(func(object objectstorage.StorableObject) {
			transferOutputToElevate := object.(*TransferOutput)

			if currentTransferOutputRealityId := transferOutputToElevate.GetRealityId(); currentTransferOutputRealityId == reality.GetId() {
				err = reality.elevateTransferOutputOfCurrentReality(transferOutputToElevate, newReality)
			} else if cachedNestedReality := reality.ledgerState.GetReality(currentTransferOutputRealityId); !cachedNestedReality.Exists() {
				err = errors.New("could not find nested reality to elevate TransferOutput")
			} else {
				cachedNestedReality.Consume(func(nestedReality objectstorage.StorableObject) {
					err = nestedReality.(*Reality).elevateTransferOutputOfNestedReality(transferOutputToElevate, reality.GetId(), newReality.GetId())
				})
			}
		})
	}

	return
}

// Private utility function that elevates the transfer output from the current reality to the new reality.
func (reality *Reality) elevateTransferOutputOfCurrentReality(transferOutput *TransferOutput, newReality *Reality) (err error) {
	for transferHash, addresses := range transferOutput.GetConsumers() {
		for _, addressHash := range addresses {
			if elevateErr := reality.elevateTransferOutput(NewTransferOutputReference(transferHash, addressHash), newReality); elevateErr != nil {
				err = elevateErr

				return
			}
		}
	}

	err = newReality.bookTransferOutput(transferOutput)

	return
}

// endregion ///////////////////////////////////////////////////////////////////////////////////////////////////////////

func (reality *Reality) GetSubRealityIdCount() (subRealityIdCount int) {
	reality.subRealityIdsMutex.RLock()
	subRealityIdCount = len(reality.subRealityIds)
	reality.subRealityIdsMutex.RUnlock()

	return
}

func (reality *Reality) UnregisterSubReality(realityId RealityId) {
	reality.subRealityIdsMutex.RLock()
	if _, subRealityIdExists := reality.subRealityIds[realityId]; subRealityIdExists {
		reality.subRealityIdsMutex.RUnlock()

		reality.subRealityIdsMutex.Lock()
		if _, subRealityIdExists := reality.subRealityIds[realityId]; subRealityIdExists {
			delete(reality.subRealityIds, realityId)

			reality.SetModified()
		}
		reality.subRealityIdsMutex.Unlock()
	} else {
		reality.subRealityIdsMutex.RUnlock()
	}
}

func (reality *Reality) RegisterSubReality(realityId RealityId) {
	reality.subRealityIdsMutex.RLock()
	if _, subRealityIdExists := reality.subRealityIds[realityId]; !subRealityIdExists {
		reality.subRealityIdsMutex.RUnlock()

		reality.subRealityIdsMutex.Lock()
		if _, subRealityIdExists := reality.subRealityIds[realityId]; !subRealityIdExists {
			reality.subRealityIds[realityId] = void

			reality.SetModified()
		}
		reality.subRealityIdsMutex.Unlock()
	} else {
		reality.subRealityIdsMutex.RUnlock()
	}
}

func (reality *Reality) elevateTransferOutputOfNestedReality(transferOutput *TransferOutput, oldParentRealityId RealityId, newParentRealityId RealityId) (err error) {
	if !reality.IsAggregated() {
		reality.replaceParentReality(oldParentRealityId, newParentRealityId)
	} else {
		reality.ledgerState.AggregateRealities(reality.GetParentRealityIds().Remove(oldParentRealityId).Add(newParentRealityId).ToList()...).Consume(func(newAggregatedReality objectstorage.StorableObject) {
			newAggregatedReality.Persist()

			err = reality.elevateTransferOutputOfCurrentReality(transferOutput, newAggregatedReality.(*Reality))
		})
	}

	return
}

func (reality *Reality) bookTransferOutput(transferOutput *TransferOutput) (err error) {
	// retrieve required variables
	realityId := reality.id
	transferOutputRealityId := transferOutput.GetRealityId()
	transferOutputAddressHash := transferOutput.GetAddressHash()
	transferOutputSpent := len(transferOutput.consumers) >= 1
	transferOutputTransferHash := transferOutput.GetTransferHash()

	// store the transferOutput if it is "new"
	if transferOutputRealityId == emptyRealityId {
		transferOutput.SetRealityId(realityId)

		reality.ledgerState.storeTransferOutput(transferOutput).Release()
	} else

	// remove old booking if the TransferOutput is currently booked in another reality
	if transferOutputRealityId != realityId {
		if oldTransferOutputBooking, err := reality.ledgerState.transferOutputBookings.Load(generateTransferOutputBookingStorageKey(transferOutputRealityId, transferOutputAddressHash, len(transferOutput.consumers) >= 1, transferOutput.GetTransferHash())); err != nil {
			return err
		} else {
			transferOutput.SetRealityId(realityId)

			reality.ledgerState.GetReality(transferOutputRealityId).Consume(func(object objectstorage.StorableObject) {
				transferOutputReality := object.(*Reality)

				// decrease transferOutputCount and remove reality if it is empty
				if transferOutputReality.DecreaseTransferOutputCount() == 0 && transferOutputReality.GetSubRealityIdCount() == 0 {
					for _, cachedParentReality := range transferOutputReality.GetParentRealities() {
						cachedParentReality.Consume(func(parentReality objectstorage.StorableObject) {
							parentReality.(*Reality).UnregisterSubReality(transferOutputRealityId)
						})
					}
					transferOutputReality.Delete()
				}
			})

			oldTransferOutputBooking.Consume(func(transferOutputBooking objectstorage.StorableObject) {
				transferOutputBooking.Delete()
			})
		}
	}

	// book the TransferOutput into the current Reality
	if transferOutputRealityId != realityId {
		reality.ledgerState.storeTransferOutputBooking(newTransferOutputBooking(realityId, transferOutputAddressHash, transferOutputSpent, transferOutputTransferHash)).Release()

		reality.IncreaseTransferOutputCount()
	}

	return
}