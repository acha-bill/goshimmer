package collectivebeacon

import (
	"fmt"
	"net/http"

	"github.com/iotaledger/goshimmer/packages/binary/drng/subtypes/collectiveBeacon/payload"
	"github.com/iotaledger/goshimmer/plugins/issuer"
	"github.com/iotaledger/hive.go/marshalutil"
	"github.com/labstack/echo"
	"github.com/labstack/gommon/log"
)

// Handler gets the current DRNG committee.
func Handler(c echo.Context) error {
	var request Request
	if err := c.Bind(&request); err != nil {
		log.Info(err.Error())
		return c.JSON(http.StatusBadRequest, Response{Error: err.Error()})
	}

	marshalUtil := marshalutil.New(request.Payload)
	parsedPayload, err := payload.Parse(marshalUtil)
	if err != nil {
		return c.JSON(http.StatusBadRequest, Response{Error: "not a valid Collective Beacon payload"})
	}

	if len(parsedPayload.Bytes()) > payload.MaxCollectiveBeaconPayloadSize {
		msg := fmt.Sprintf("maximum payload size of %d bytes exceeded", payload.MaxCollectiveBeaconPayloadSize)
		log.Info(msg)
		return c.JSON(http.StatusBadRequest, Response{Error: msg})
	}

	msg, err := issuer.IssuePayload(parsedPayload)
	if err != nil {
		return c.JSON(http.StatusBadRequest, Response{Error: err.Error()})
	}
	return c.JSON(http.StatusOK, Response{ID: msg.Id().String()})
}

// Response is the HTTP response from broadcasting a collective beacon message.
type Response struct {
	ID    string `json:"id,omitempty"`
	Error string `json:"error,omitempty"`
}

// Request is a request containing a collective beacon response.
type Request struct {
	Payload []byte `json:"payload"`
}
