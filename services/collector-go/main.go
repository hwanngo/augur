// Augur log collector (Go) — the first extracted microservice (ADR-0002 order #1).
//
// Reads a JSONL log file, ships the events to the Python detection-engine over gRPC
// (ADR-0003), and prints the ranked detections it gets back. This is the polyglot seam:
// a high-throughput Go collector talking to the Python engine that owns the scenario
// library + matching logic.
//
// Run:  go run . [path-to.jsonl] [min_proximity]
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	pb "augur/collector/gen/fsrpcv1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	addr := envOr("FS_ENGINE_ADDR", "localhost:50051")
	path := "../../sample_data/corpus/enterprise_day.jsonl"
	minProx := 0.30
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	if len(os.Args) > 2 {
		if v, err := strconv.ParseFloat(os.Args[2], 64); err == nil {
			minProx = v
		}
	}

	events, err := readJSONL(path)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("collector: read %d events from %s\n", len(events), path)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fatal(err)
	}
	defer conn.Close()
	client := pb.NewDetectorClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	resp, err := client.Analyze(ctx, &pb.AnalyzeRequest{Events: events, MinProximity: minProx})
	if err != nil {
		fatal(fmt.Errorf("Analyze RPC failed (is the engine server running on %s?): %w", addr, err))
	}

	fmt.Printf("engine returned %d detection(s) at min_proximity=%.2f:\n", len(resp.Detections), minProx)
	for _, d := range resp.Detections {
		fmt.Printf("  [%-8s] %-14s %3.0f%%  %d/%d  %-42s hosts=%v\n",
			d.Severity, d.ScenarioId, d.Proximity*100, d.MatchedSteps, d.TotalSteps, trunc(d.Name, 42), d.AffectedHosts)
	}
}

func readJSONL(path string) ([]*pb.RawEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []*pb.RawEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if len(line) == 0 {
			continue
		}
		out = append(out, &pb.RawEvent{Json: line})
	}
	return out, sc.Err()
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
