package sdk

import (
	"testing"

	abci "github.com/gnolang/gno/pkgs/bft/abci/types"
	"github.com/stretchr/testify/require"
)

type nopTestHandler struct{}

func (_ nopTestHandler) Process(_ Context, _ Msg) Result {
	return Result{}
}

func (_ nopTestHandler) Query(_ Context, _ abci.RequestQuery) abci.ResponseQuery {
	return abci.ResponseQuery{}
}

func TestRouter(t *testing.T) {
	rtr := NewRouter()

	// require panic on invalid route
	require.Panics(t, func() {
		rtr.AddRoute("*", nopTestHandler{})
	})

	rtr.AddRoute("testRoute", nopTestHandler{})
	h := rtr.Route("testRoute")
	require.NotNil(t, h)

	// require panic on duplicate route
	require.Panics(t, func() {
		rtr.AddRoute("testRoute", nopTestHandler{})
	})
}
