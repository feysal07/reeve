package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/feysal07/reeve/internal/telemetry"
)

// runCollect receives what agents report and writes it to a store.
//
// It is an OpenTelemetry endpoint, so agents need no plugin: each one already knows
// how to export, and the compiler writes the destination into their managed settings.
// What this adds over an off-the-shelf collector is normalisation across vendors,
// cost computed centrally from tokens, and attribution resolved from a mapping the
// operator controls rather than from an attribute the client asserts.
func runCollect(args []string) error {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:4318", "address to listen on")
	store := fs.String("store", "", "append normalised events to this file (required)")
	teamsPath := fs.String("teams", "", "team mapping file, so attribution does not rely on client-set attributes")
	pricesPath := fs.String("prices", "", "price table, for cost computed at your rates rather than list")
	verbose := fs.Bool("verbose", false, "log every batch received")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *store == "" {
		// The store path is deliberately not defaulted. The file records who did
		// what and when, so creating it somewhere the operator did not choose is
		// the wrong kind of convenience. The error therefore has to teach.
		return fmt.Errorf(`--store is required, because the collector has nowhere to put events without it.

It is not defaulted on purpose: the file records who did what and when, and that
should land where you chose rather than where Reeve guessed.

  reeve collect --store ./events.jsonl

Add a team mapping so attribution does not rely on what the agents claim about
themselves, and --prices so cost reflects your rates rather than list:

  reeve collect --store ./events.jsonl --teams ./examples/telemetry/teams.yaml

Then point an agent at it:

  OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
  OTEL_EXPORTER_OTLP_PROTOCOL=http/json

See docs/TELEMETRY.md`)
	}

	prices := telemetry.DefaultPrices
	if *pricesPath != "" {
		p, err := telemetry.LoadPrices(*pricesPath)
		if err != nil {
			return err
		}
		prices = p
	} else {
		fmt.Fprintln(os.Stderr,
			"warning: using the built-in price table at published list rates. Costs are estimates;\n"+
				"         supply --prices with your own rates before using them for chargeback.")
	}

	var teams *telemetry.TeamMap
	if *teamsPath != "" {
		t, err := telemetry.LoadTeams(*teamsPath)
		if err != nil {
			return err
		}
		teams = t
	} else {
		fmt.Fprintln(os.Stderr,
			"warning: no team mapping supplied, so events carry no team attribution.")
	}

	st, err := telemetry.OpenStore(*store)
	if err != nil {
		return err
	}
	defer st.Close()

	dec := &telemetry.Decoder{Prices: prices}
	if teams != nil {
		dec.Teams = teams
	}

	c := &collector{dec: dec, store: st, verbose: *verbose}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/metrics", c.handle(dec.DecodeMetrics, dec.DecodeMetricsProto))
	mux.HandleFunc("/v1/logs", c.handle(dec.DecodeLogs, dec.DecodeLogsProto))
	mux.HandleFunc("/v1/traces", c.acceptAndIgnore)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/stats", c.stats)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("Collector listening on http://%s\n", *addr)
	fmt.Printf("  store  : %s\n", st.Path())
	fmt.Printf("  teams  : %s\n", orDash(*teamsPath))
	fmt.Printf("  prices : %s\n", orDash(*pricesPath))
	fmt.Printf("\nPoint agents at it with OTLP over HTTP using JSON encoding, for example:\n")
	fmt.Printf("  OTEL_EXPORTER_OTLP_ENDPOINT=http://%s\n", *addr)
	fmt.Printf("  OTEL_EXPORTER_OTLP_PROTOCOL=http/json\n\n")

	// Shut down on a signal so the store is closed cleanly and a partially written
	// final line cannot be left behind.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		fmt.Println("\nshutting down")
		srv.Close()
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

type collector struct {
	dec     *telemetry.Decoder
	store   *telemetry.Store
	verbose bool

	mu       sync.Mutex
	received int
	written  int
	rejected int
}

// maxBody caps a request. An agent batching a long session can send a large payload,
// but an unbounded read is a way to exhaust memory on a shared host.
const maxBody = 32 << 20

// handle serves one OTLP signal in either encoding.
//
// The encoding is chosen by Content-Type, which is what the specification says and
// what every exporter sets. Protobuf is the default for most of them, so guessing
// wrong here would look to an operator like an agent that had stopped reporting.
func (c *collector) handle(decodeJSON, decodeProto func([]byte) ([]telemetry.Event, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		decode := decodeJSON
		if strings.Contains(r.Header.Get("Content-Type"), "protobuf") {
			decode = decodeProto
		}

		events, err := decode(body)
		if err != nil {
			c.count(&c.rejected, 1)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		c.count(&c.received, 1)
		if len(events) > 0 {
			if err := c.store.Append(events...); err != nil {
				// A store failure is a server error: the agent should retry rather
				// than believe its telemetry was accepted.
				http.Error(w, "store", http.StatusInternalServerError)
				return
			}
			c.count(&c.written, len(events))
		}
		if c.verbose {
			fmt.Printf("%s %s -> %d events\n", time.Now().Format(time.RFC3339), r.URL.Path, len(events))
		}

		// OTLP expects a JSON object in reply; an empty one means everything was
		// accepted with nothing rejected.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "{}")
	}
}

// acceptAndIgnore takes trace payloads without storing them. Accepting is deliberate:
// an agent whose trace export fails may log errors or back off its other exports, and
// traces add little that the event stream does not already carry.
func (c *collector) acceptAndIgnore(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, io.LimitReader(r.Body, maxBody))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "{}")
}

func (c *collector) count(field *int, n int) {
	c.mu.Lock()
	*field += n
	c.mu.Unlock()
}

func (c *collector) stats(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"batchesReceived":%d,"eventsWritten":%d,"batchesRejected":%d}`+"\n",
		c.received, c.written, c.rejected)
}
