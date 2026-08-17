// Command control-plane is the jumpgate control plane: identity, authorization,
// JIT/approvals, vault, audit, and the API. M1 serves only /healthz.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/trevex/jumpgate/control-plane/internal/httpapi"
)

func main() {
	addr := os.Getenv("JUMPGATE_LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("control-plane listening on %s", addr)                      //nolint:gosec // addr is from env, not user input
	if err := http.ListenAndServe(addr, httpapi.NewRouter()); err != nil { //nolint:gosec // M1 stub; timeout will be added when server is hardened
		log.Fatal(err)
	}
}
