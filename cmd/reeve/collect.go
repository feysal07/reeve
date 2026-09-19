package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
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
	metricsAddr := fs.String("metrics-addr", "", "serve Prometheus metrics on this address, on its own listener")
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

	metrics := telemetry.NewMetrics(version, st.Path())
	c := &collector{dec: dec, store: st, verbose: *verbose, metrics: metrics}

	// Metrics get their own listener rather than another route on the OTLP mux.
	//
	// The OTLP port is the one agents reach, which in most deployments means it is
	// exposed to every developer machine. The metrics there would tell anyone who
	// asked which agents are in use, how much is being spent and how busy the
	// organisation is, none of which is any of their business. Keeping the two apart
	// makes the exposure decision once, per port, rather than once per route.
	// Bound before anything starts, so the common failure can be explained rather than
	// reported. 4318 being the default is exactly why it is worth keeping and exactly
	// why something else is often already on it.
	otlpLn, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf(`listen on %s: %w

4318 is the default port for OTLP over HTTP, which is why an agent finds this
collector without being told where it is, and why something else is often already
there: a Docker Desktop collector, a WSL one, or another copy of this.

Give it a port of its own and tell the agents about that instead:

  reeve collect --addr 127.0.0.1:14318 --store %s
  OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:14318

In a container, keep 4318 on the inside and remap it on the outside:

  docker run -p 14318:4318 ...`, *addr, err, *store)
	}

	var metricsLn net.Listener
	if *metricsAddr != "" {
		ln, err := net.Listen("tcp", *metricsAddr)
		if err != nil {
			// Refuse to start rather than run without the endpoint. A collector that
			// is up but cannot be scraped looks healthy from every direction except
			// the one that would tell you it had stopped receiving anything.
			return fmt.Errorf("metrics listener on %s: %w", *metricsAddr, err)
		}
		metricsLn = ln
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/metrics", c.handle("metrics", dec.DecodeMetrics, dec.DecodeMetricsProto))
	mux.HandleFunc("/v1/logs", c.handle("logs", dec.DecodeLogs, dec.DecodeLogsProto))
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

	var metricsSrv *http.Server
	if metricsLn != nil {
		mmux := http.NewServeMux()
		mmux.Handle("/metrics", metrics)
		mmux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "ok")
		})
		metricsSrv = &http.Server{Handler: mmux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := metricsSrv.Serve(metricsLn); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "metrics listener: %v\n", err)
			}
		}()
	}

	fmt.Printf("Collector listening on http://%s\n", *addr)
	fmt.Printf("  store  : %s\n", st.Path())
	fmt.Printf("  teams  : %s\n", orDash(*teamsPath))
	fmt.Printf("  prices : %s\n", orDash(*pricesPath))
	fmt.Printf("  metrics: %s\n", orDash(*metricsAddr))
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
		// Drain rather than cut. A batch already written to the store, whose
		// response is lost because the connection went away, is retried by the
		// agent, and the same events are recorded a second time. Under a rolling
		// restart in Kubernetes that stops being rare, and duplicated events
		// overstate both the audit trail and the bill without anything failing.
		//
		// The timeout is shorter than any sensible termination grace period, so
		// the process exits on its own terms rather than being killed.
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			srv.Close()
		}
		if metricsSrv != nil {
			metricsSrv.Shutdown(ctx)
		}
	}()

	if err := srv.Serve(otlpLn); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

type collector struct {
	dec     *telemetry.Decoder
	store   *telemetry.Store
	verbose bool
	metrics *telemetry.Metrics

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
func (c *collector) handle(signal string, decodeJSON, decodeProto func([]byte) ([]telemetry.Event, error)) http.HandlerFunc {
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
			c.metrics.BatchRejected(signal)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		c.count(&c.received, 1)
		c.metrics.BatchReceived(signal)
		if len(events) > 0 {
			if err := c.store.Append(events...); err != nil {
				// A store failure is a server error: the agent should retry rather
				// than believe its telemetry was accepted.
				c.metrics.StoreWriteFailed()
				http.Error(w, "store", http.StatusInternalServerError)
				return
			}
			c.count(&c.written, len(events))
			// Counted only after the write succeeded, so the metric describes what
			// is in the store rather than what was decoded on the way to it.
			c.metrics.RecordEvents(events)
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
	c.metrics.BatchReceived("traces")
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
