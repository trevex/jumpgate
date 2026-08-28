// Package output provides a shared renderer so CLI commands emit results
// identically as either a human-readable table or JSON.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Table describes a human-readable table.
type Table struct {
	Headers []string
	Rows    [][]string
}

// Render writes v as indented JSON (format=="json") or the Table tv
// (format=="table"). tv may be nil for table (renders nothing). Unknown format
// is an error.
func Render(w io.Writer, format string, v any, tv *Table) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	case "table":
		if tv == nil {
			return nil
		}
		return renderTable(w, tv)
	default:
		return fmt.Errorf("unknown output format %q (want table|json)", format)
	}
}

// RenderProto renders a single proto.Message as protojson (json) or the Table
// (table). Unknown format is an error.
func RenderProto(w io.Writer, format string, msg proto.Message, tv *Table) error {
	switch format {
	case "json":
		b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(msg)
		if err != nil {
			return err
		}
		b = append(b, '\n')
		_, err = w.Write(b)
		return err
	case "table":
		return Render(w, "table", nil, tv)
	default:
		return fmt.Errorf("unknown output format %q (want table|json)", format)
	}
}

// RenderProtoList renders a slice of proto.Messages as a JSON array (json) or
// the Table (table). Unknown format is an error.
func RenderProtoList(w io.Writer, format string, msgs []proto.Message, tv *Table) error {
	switch format {
	case "json":
		raw := make([]json.RawMessage, 0, len(msgs))
		for _, msg := range msgs {
			b, err := protojson.Marshal(msg)
			if err != nil {
				return err
			}
			raw = append(raw, json.RawMessage(b))
		}
		b, err := json.MarshalIndent(raw, "", "  ")
		if err != nil {
			return err
		}
		b = append(b, '\n')
		_, err = w.Write(b)
		return err
	case "table":
		return Render(w, "table", nil, tv)
	default:
		return fmt.Errorf("unknown output format %q (want table|json)", format)
	}
}

func renderTable(w io.Writer, tv *Table) error {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, strings.Join(tv.Headers, "\t")); err != nil {
		return err
	}
	for _, row := range tv.Rows {
		if _, err := fmt.Fprintln(tw, strings.Join(row, "\t")); err != nil {
			return err
		}
	}
	return tw.Flush()
}
