package client

import (
	"io"
	"strings"

	"github.com/iotaledger/goshimmer/packages/metrics"
	"github.com/iotaledger/goshimmer/plugins/analysis/packet"
	"github.com/iotaledger/goshimmer/plugins/autopeering"
	"github.com/iotaledger/goshimmer/plugins/autopeering/local"
	"github.com/iotaledger/hive.go/identity"
	"github.com/mr-tron/base58"
)

// EventDispatchers holds the Heartbeat function.
type EventDispatchers struct {
	// Heartbeat defines the Heartbeat function.
	Heartbeat func(heartbeat *packet.Heartbeat)
}

func sendHeartbeat(w io.Writer, hb *packet.Heartbeat) {
	var out strings.Builder
	for _, value := range hb.OutboundIDs {
		out.WriteString(base58.Encode(value))
	}
	var in strings.Builder
	for _, value := range hb.InboundIDs {
		in.WriteString(base58.Encode(value))
	}
	log.Debugw(
		"Heartbeat",
		"nodeID", base58.Encode(hb.OwnID),
		"outboundIDs", out.String(),
		"inboundIDs", in.String(),
	)

	data, err := packet.NewHeartbeatMessage(hb)
	if err != nil {
		log.Info(err, " - heartbeat message skipped")
		return
	}

	if _, err = w.Write(data); err != nil {
		log.Debugw("Error while writing to connection", "Description", err)
	}
	// trigger AnalysisOutboundBytes event
	metrics.Events().AnalysisOutboundBytes.Trigger(uint64(len(data)))
}

func createHeartbeat() *packet.Heartbeat {
	// get own ID
	nodeID := make([]byte, len(identity.ID{}))
	if local.GetInstance() != nil {
		copy(nodeID, local.GetInstance().ID().Bytes())
	}

	var outboundIDs [][]byte
	var inboundIDs [][]byte

	// get outboundIDs (chosen neighbors)
	outgoingNeighbors := autopeering.Selection().GetOutgoingNeighbors()
	outboundIDs = make([][]byte, len(outgoingNeighbors))
	for i, neighbor := range outgoingNeighbors {
		outboundIDs[i] = make([]byte, len(identity.ID{}))
		copy(outboundIDs[i], neighbor.ID().Bytes())
	}

	// get inboundIDs (accepted neighbors)
	incomingNeighbors := autopeering.Selection().GetIncomingNeighbors()
	inboundIDs = make([][]byte, len(incomingNeighbors))
	for i, neighbor := range incomingNeighbors {
		inboundIDs[i] = make([]byte, len(identity.ID{}))
		copy(inboundIDs[i], neighbor.ID().Bytes())
	}

	return &packet.Heartbeat{OwnID: nodeID, OutboundIDs: outboundIDs, InboundIDs: inboundIDs}
}
