package cmd

import (
	"errors"

	"github.com/trevex/jumpgate/cli/internal/wardenclient"
)

// newClient resolves the effective context and returns a bearer-authed warden
// client. It is the shared entry point for every noun command: it fails with a
// clear message when the warden address or token is missing so subcommands can
// simply return the error up to the root.
func newClient() (*wardenclient.Client, error) {
	ctx, err := resolveContext()
	if err != nil {
		return nil, err
	}
	if ctx.WardenAddr == "" {
		return nil, errors.New("warden address is not set; pass --warden-addr, set JUMPGATE_WARDEN_ADDR, or run `jumpgate login`")
	}
	if ctx.Token == "" {
		return nil, errors.New("not logged in; run `jumpgate login`")
	}
	return wardenclient.New(ctx.WardenAddr, ctx.Token), nil
}
