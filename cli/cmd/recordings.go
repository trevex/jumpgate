package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/trevex/jumpgate/cli/internal/output"
	recordingv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/recording/v1"
)

var recordingHeaders = []string{"SESSION", "PROTOCOL", "STATUS", "SIZE", "SHA256"}

func recordingRow(r *recordingv1.Recording) []string {
	return []string{
		r.GetSessionId(),
		r.GetProtocol(),
		r.GetStatus(),
		fmt.Sprintf("%d", r.GetSizeBytes()),
		shortSHA(r.GetSha256()),
	}
}

// shortSHA truncates a hex digest to its first 12 characters for compact table
// display, leaving shorter values untouched.
func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

var recordingsCmd = &cobra.Command{
	Use:   "recordings",
	Short: "List, inspect, and download session recordings",
}

var (
	recordingsListUser  string
	recordingsListAsset string
)

var recordingsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List session recordings",
	Args:  cobra.NoArgs,
	RunE:  runRecordingsList,
}

var recordingsGetCmd = &cobra.Command{
	Use:   "get <session-id>",
	Short: "Show a session recording's metadata",
	Args:  cobra.ExactArgs(1),
	RunE:  runRecordingsGet,
}

var recordingsDownloadFile string

var recordingsDownloadCmd = &cobra.Command{
	Use:   "download <session-id>",
	Short: "Download a session recording to a file",
	Args:  cobra.ExactArgs(1),
	RunE:  runRecordingsDownload,
}

func init() {
	recordingsListCmd.Flags().StringVar(&recordingsListUser, "user", "", "filter by user id or email")
	recordingsListCmd.Flags().StringVar(&recordingsListAsset, "asset", "", "filter by asset id or name")

	recordingsDownloadCmd.Flags().StringVarP(&recordingsDownloadFile, "file", "f", "", "output file (default <session-id>.cast)")

	recordingsCmd.AddCommand(recordingsListCmd)
	recordingsCmd.AddCommand(recordingsGetCmd)
	recordingsCmd.AddCommand(recordingsDownloadCmd)
	rootCmd.AddCommand(recordingsCmd)
}

func runRecordingsList(cmd *cobra.Command, _ []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	list := &recordingv1.ListRecordingsRequest{PageSize: 100}
	if recordingsListUser != "" {
		userID, err := resolveUserID(cmd.Context(), cl, recordingsListUser)
		if err != nil {
			return err
		}
		list.UserId = userID
	}
	if recordingsListAsset != "" {
		assetID, err := cl.ResolveAsset(cmd.Context(), recordingsListAsset)
		if err != nil {
			return err
		}
		list.AssetId = assetID
	}

	req := connect.NewRequest(list)
	cl.Authorize(req)
	resp, err := cl.Recording().ListRecordings(cmd.Context(), req)
	if err != nil {
		return err
	}

	recs := resp.Msg.GetRecordings()
	rows := make([][]string, 0, len(recs))
	msgs := make([]proto.Message, 0, len(recs))
	for _, r := range recs {
		rows = append(rows, recordingRow(r))
		msgs = append(msgs, r)
	}
	return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{
		Headers: recordingHeaders,
		Rows:    rows,
	})
}

func runRecordingsGet(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	req := connect.NewRequest(&recordingv1.GetRecordingRequest{SessionId: args[0]})
	cl.Authorize(req)
	resp, err := cl.Recording().GetRecording(cmd.Context(), req)
	if err != nil {
		return err
	}

	r := resp.Msg
	return output.RenderProto(cmd.OutOrStdout(), flagOutput, r, &output.Table{
		Headers: recordingHeaders,
		Rows:    [][]string{recordingRow(r)},
	})
}

func runRecordingsDownload(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	sessionID := args[0]
	req := connect.NewRequest(&recordingv1.GetRecordingRequest{SessionId: sessionID})
	cl.Authorize(req)
	resp, err := cl.Recording().GetRecordingDownload(cmd.Context(), req)
	if err != nil {
		return err
	}

	out := recordingsDownloadFile
	if out == "" {
		out = sessionID + ".cast"
	}

	if err := streamToFile(cmd.Context(), resp.Msg.GetUrl(), out); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", out)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Replay with: asciinema play %s\n", out)
	return nil
}

// streamToFile fetches url and streams its body to path. A non-200 response is
// an error; the presigned URL is fetched unauthenticated (it carries its own
// credentials in the query string).
func streamToFile(ctx context.Context, url, path string) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("downloading recording: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading recording: unexpected status %s", httpResp.Status)
	}

	f, err := os.Create(path) // #nosec G304 -- path is the user-chosen output location
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	if _, err := io.Copy(f, httpResp.Body); err != nil {
		return fmt.Errorf("writing recording: %w", err)
	}
	return f.Close()
}
