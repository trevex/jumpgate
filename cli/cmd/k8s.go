package cmd

import (
	"fmt"
	"text/template"
	"time"

	"github.com/spf13/cobra"

	"github.com/trevex/jumpgate/cli/internal/execcred"
)

var k8sCmd = &cobra.Command{Use: "k8s", Short: "Kubernetes access (exec-plugin + kubeconfig)"}

var k8sAuthCmd = &cobra.Command{
	Use:   "auth <asset>",
	Short: "client-go exec-plugin: print an ExecCredential (cached bearer token)",
	Args:  cobra.ExactArgs(1),
	RunE:  runK8sAuth,
}

var k8sKubeconfigCmd = &cobra.Command{
	Use:   "kubeconfig <asset>",
	Short: "Print a kubeconfig wiring kubectl through jumpgate to the cluster",
	Args:  cobra.ExactArgs(1),
	RunE:  runK8sKubeconfig,
}

func runK8sAuth(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	client, err := newClient()
	if err != nil {
		return err
	}
	assetID, err := client.ResolveAsset(ctx, args[0])
	if err != nil {
		return err
	}
	cache, err := execcred.DefaultCache()
	if err != nil {
		return err
	}
	if e, ok := cache.Load(assetID); ok {
		return printExecCredential(cmd, e.Token, e.ExpiresAt)
	}
	token, _, expiresAt, err := client.CreateKubernetesSession(ctx, assetID)
	if err != nil {
		return err
	}
	if err := cache.Store(assetID, token, expiresAt); err != nil {
		return err // fail closed: if we can't cache, error rather than mint every kubectl call
	}
	return printExecCredential(cmd, token, expiresAt)
}

func printExecCredential(cmd *cobra.Command, token string, expiry time.Time) error {
	out, err := execcred.MarshalExecCredential(token, expiry)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(out))
	return nil
}

const kubeconfigTmpl = `apiVersion: v1
kind: Config
clusters:
- name: {{.Name}}
  cluster:
    server: https://{{.Server}}
    certificate-authority: {{.CAFile}}
contexts:
- name: {{.Name}}
  context:
    cluster: {{.Name}}
    user: {{.Name}}
current-context: {{.Name}}
users:
- name: {{.Name}}
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: jumpgate
      args: ["k8s", "auth", "{{.Asset}}"]
      interactiveMode: Never
`

func runK8sKubeconfig(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	client, err := newClient()
	if err != nil {
		return err
	}
	cctx, err := resolveContext()
	if err != nil {
		return err
	}
	if cctx.CAFile == "" {
		return fmt.Errorf("no CA configured; pass --ca or run `jumpgate login` with a CA so kubectl can verify the gateway")
	}
	assetID, err := client.ResolveAsset(ctx, args[0])
	if err != nil {
		return err
	}
	// The gateway endpoint is the stable LB address; learn it by minting once.
	_, gatewayEndpoint, _, err := client.CreateKubernetesSession(ctx, assetID)
	if err != nil {
		return err
	}
	return template.Must(template.New("kc").Parse(kubeconfigTmpl)).Execute(cmd.OutOrStdout(), map[string]string{
		"Name":   "jumpgate-" + assetID,
		"Server": gatewayEndpoint,
		"CAFile": cctx.CAFile,
		"Asset":  assetID, // the exec-plugin re-resolves; a UUID short-circuits with no RPC
	})
}

func init() {
	k8sCmd.AddCommand(k8sAuthCmd)
	k8sCmd.AddCommand(k8sKubeconfigCmd)
	rootCmd.AddCommand(k8sCmd)
}
