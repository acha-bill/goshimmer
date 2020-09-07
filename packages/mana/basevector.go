package mana

import (
	"errors"
	"time"

	"github.com/iotaledger/hive.go/identity"
)

// BaseManaVector represents a base mana vector
type BaseManaVector struct {
	vector     map[identity.ID]*BaseMana
	vectorType Type
}

// NewBaseManaVector creates and returns a new base mana vector for the specified type
func NewBaseManaVector(vectorType Type) *BaseManaVector {
	return &BaseManaVector{
		vector:     make(map[identity.ID]*BaseMana),
		vectorType: vectorType,
	}
}

// BookMana books mana for a transaction.
func (bmv *BaseManaVector) BookMana(txInfo *TxInfo) {
	// first, revoke mana from previous owners
	for _, inputInfo := range txInfo.InputInfos {
		// which node did the input pledge mana to?
		pledgeNodeID := inputInfo.PledgeID[bmv.vectorType]
		if _, exist := bmv.vector[pledgeNodeID]; !exist {
			// first time we see this node
			bmv.vector[pledgeNodeID] = &BaseMana{}
		}
		// save old mana
		oldMana := bmv.vector[pledgeNodeID]
		// revoke BM1
		bmv.vector[pledgeNodeID].revokeBaseMana1(inputInfo.Amount, txInfo.TimeStamp)

		// trigger events
		Events().Revoked.Trigger(&RevokedEvent{pledgeNodeID, inputInfo.Amount, txInfo.TimeStamp, bmv.vectorType})
		Events().Updated.Trigger(&UpdatedEvent{pledgeNodeID, *oldMana, *bmv.vector[pledgeNodeID], bmv.vectorType})
	}
	// second, pledge mana to new nodes
	pledgeNodeID := txInfo.PledgeID[bmv.vectorType]
	if _, exist := bmv.vector[pledgeNodeID]; !exist {
		// first time we see this node
		bmv.vector[pledgeNodeID] = &BaseMana{}
	}
	// save it for proper event trigger
	oldMana := bmv.vector[pledgeNodeID]
	// actually pledge and update
	bm1Pledged, bm2Pledged := bmv.vector[pledgeNodeID].pledgeAndUpdate(txInfo)

	// trigger events
	Events().Pledged.Trigger(&PledgedEvent{pledgeNodeID, bm1Pledged, bm2Pledged, txInfo.TimeStamp, bmv.vectorType})
	Events().Updated.Trigger(&UpdatedEvent{pledgeNodeID, *oldMana, *bmv.vector[pledgeNodeID], bmv.vectorType})
}

// Update updates the mana entries for a particular node wrt time.
func (bmv *BaseManaVector) Update(nodeID identity.ID, t time.Time) error {
	if _, exist := bmv.vector[nodeID]; !exist {
		return errors.New("node not present in base mana vector")
	}
	oldMana := bmv.vector[nodeID]
	if err := bmv.vector[nodeID].update(t); err != nil {
		return err
	}
	Events().Updated.Trigger(&UpdatedEvent{nodeID, *oldMana, *bmv.vector[nodeID], bmv.vectorType})
	return nil
}

// UpdateAll updates all entries in the base mana vector wrt to `t`.
func (bmv *BaseManaVector) UpdateAll(t time.Time) error {
	for nodeID := range bmv.vector {
		if err := bmv.Update(nodeID, t); err != nil {
			return err
		}
	}
	return nil
}

// GetWeightedMana returns the combination of Effective Base Mana 1 & 2, weighted by weight.
// mana = EBM1 * weight + EBM2 * ( 1- weight), where weight is in [0,1].
func (bmv *BaseManaVector) GetWeightedMana(nodeID identity.ID, weight float64) (float64, error) {
	if _, exist := bmv.vector[nodeID]; !exist {
		return 0.0, errors.New("node not present in base mana vector")
	}
	if weight < 0.0 || weight > 1.0 {
		return 0.0, errors.New("invalid weight parameter, outside of [0,1]")
	}
	bmv.Update(nodeID, time.Now())
	baseMana := bmv.vector[nodeID]
	return baseMana.EffectiveBaseMana1*weight + baseMana.EffectiveBaseMana2*(1-weight), nil
}

// GetMana returns the 50 - 50 split combination of Effective Base Mana 1 & 2.
func (bmv *BaseManaVector) GetMana(nodeID identity.ID) (float64, error) {
	return bmv.GetWeightedMana(nodeID, 0.5)
}