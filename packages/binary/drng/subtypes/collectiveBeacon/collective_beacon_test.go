package collectiveBeacon

import (
	"encoding/hex"
	"testing"

	"github.com/iotaledger/goshimmer/packages/binary/drng/state"
	"github.com/iotaledger/goshimmer/packages/binary/drng/subtypes/collectiveBeacon/events"
	"github.com/iotaledger/hive.go/crypto/ed25519"
	"github.com/stretchr/testify/require"
)

var (
	eventTest         *events.CollectiveBeaconEvent
	prevSignatureTest []byte
	signatureTest     []byte
	dpkTest           []byte
	issuerPK          ed25519.PublicKey
	stateTest         *state.State
)

func init() {
	prevSignatureTest, _ = hex.DecodeString("a339cd01770c4709ecdce54be69df7c180a24bcc5488f50cf1fe9152771c9b66390e300bd1ab74fdcd9e27696ab4665d1539d13654af83d0f5e911b1368ed55072402dd35576630acd9992b126d1aada546dcf6b1f15b8bc3a45b423f347ab28")
	signatureTest, _ = hex.DecodeString("904fbc91df59859c9f414d179dbf544fd3a850323b07cdf3e34659d57331a04d2172004745f7f485bc6944836c140eff17995732aa2ea8cef78580c3c9eae31c0a1a1ee844091c8af2ab6d139a3b28d85f921afab4557c601d322e9f5b06c092")
	dpkTest, _ = hex.DecodeString("8b5f2576d1c23aced651720ecd03165c4d53a4d098a7111b7874998bd0a36414454d5079a60ccb244faedf17d0022984")
	kp := ed25519.GenerateKeyPair()
	issuerPK = kp.PublicKey

	eventTest = &events.CollectiveBeaconEvent{
		IssuerPublicKey: issuerPK,
		InstanceID:      1,
		Round:           1,
		PrevSignature:   prevSignatureTest,
		Signature:       signatureTest,
		Dpk:             dpkTest,
	}

	stateTest = state.New(state.SetCommittee(
		&state.Committee{
			InstanceID:    1,
			Threshold:     3,
			Identities:    []ed25519.PublicKey{issuerPK},
			DistributedPK: dpkTest,
		}))
}

func TestVerifySignature(t *testing.T) {
	err := verifySignature(eventTest)
	require.NoError(t, err)
}

func TestGetRandomness(t *testing.T) {
	_, err := ExtractRandomness(eventTest.Signature)
	require.NoError(t, err)
}

func TestProcessBeacon(t *testing.T) {
	err := ProcessBeacon(stateTest, eventTest)
	require.NoError(t, err)
}
