// A second third-party WebTransport CLIENT against this tree's server (WT-153).
//
// `c99_server_client.py` proves the server against pywebtransport (aioquic underneath), and one
// implementation is not a matrix: a server that happened to suit aioquic's habits would look correct.
// This is the second, and it shares nothing with the first -- a different language, a different QUIC
// stack (quic-go) and a different WebTransport layer (webtransport-go).
//
// It does what the Python client does, deliberately, so the runner's two assertions mean the same
// thing for both: open a session, send a message on a bidirectional stream, then wait for the message
// the server sends on a stream IT opens. It prints one JSON object and exits non-zero unless the
// session was established AND the server's message arrived -- a client that only prints is a client
// whose failure nobody notices.
//
// The C99 server's identity is generated in memory when it starts and regenerated on the next run
// (its `--json` report prints the fingerprint, but only when the process exits), so there is nothing to
// pin it to out of band: this client verifies nothing, exactly as the Python one does, and the harness
// is what makes the two ends trustworthy -- both containers on one private network, the peer joined to
// the server's own namespace.
//
// Usage:  wt-go-client --host 127.0.0.1 --port 54070 --path / --message hello-from-go [--timeout 8]
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3/qlog"
	webtransport "github.com/quic-go/webtransport-go"
)

type report struct {
	Role           string `json:"role"`
	Implementation string `json:"implementation"`
	URL            string `json:"url"`
	Established    bool   `json:"established"`
	Status         int    `json:"status,omitempty"`
	SentBytes      int    `json:"sentBytes"`
	ReceivedBytes  int    `json:"receivedBytes"`
	Received       string `json:"received"`
	Error          string `json:"error,omitempty"`
}

// serverMessage reads the message the server sends on a stream it opens, or reports that none arrived
// inside the timeout. A server that accepts a session and then says nothing is a different result from
// one that refuses, and both are different from a timeout.
func serverMessage(ctx context.Context, session *webtransport.Session) ([]byte, error) {
	stream, err := session.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(stream)
}

func run(host string, port int, path string, message string, timeout time.Duration, allCurves *bool) report {
	url := fmt.Sprintf("https://%s:%d%s", host, port, path)
	result := report{
		Role:           "peer-client",
		Implementation: "quic-go/webtransport-go 0.11.1",
		URL:            url,
		Received:       "",
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // see the trust note above
	if !*allCurves {
		// A key exchange the server does not offer is not a session: Go's default ClientHello leads with
		// the X25519MLKEM768 hybrid, and the C99 server offers X25519 only and answers a key share it
		// cannot use with silence rather than with a HelloRetryRequest, so the handshake never starts.
		// Offering X25519 alone is what makes this client a proof of the server rather than of the
		// curve list; `--all-curves` is how the silence itself is reproduced.
		tlsConfig.CurvePreferences = []tls.CurveID{tls.X25519}
	}
	dialer := &webtransport.Dialer{
		TLSClientConfig: tlsConfig,
		// webtransport-go requires partial delivery of reset streams, and refuses to dial without it;
		// datagrams are enabled because the server's datagram exchange is the same session.
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
			// qlog is written only when QLOGDIR names a directory, which is what an investigation into a
			// handshake that never starts needs: the server's own counters cannot say what it never saw.
			Tracer: qlog.DefaultConnectionTracer,
		},
	}
	defer dialer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	response, session, err := dialer.Dial(ctx, url, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer session.CloseWithError(0, "") //nolint:errcheck // the report is what matters, not the close
	result.Status = response.StatusCode
	result.Established = true

	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		result.Error = "open stream: " + err.Error()
		return result
	}
	if _, err := stream.Write([]byte(message)); err != nil {
		result.Error = "write: " + err.Error()
		return result
	}
	if err := stream.Close(); err != nil {
		result.Error = "close stream: " + err.Error()
		return result
	}
	result.SentBytes = len(message)

	data, err := serverMessage(ctx, session)
	if err != nil {
		result.Error = "the server's own message: " + err.Error()
		return result
	}
	result.ReceivedBytes = len(data)
	result.Received = string(data)
	return result
}

func main() {
	host := flag.String("host", "127.0.0.1", "the address the C99 server listens on")
	port := flag.Int("port", 0, "the UDP port the C99 server listens on")
	path := flag.String("path", "/", "the request path")
	message := flag.String("message", "hello-from-go", "the message to send on a stream")
	timeoutSeconds := flag.Float64("timeout", 8.0, "seconds to wait for the session and the server's message")
	allCurves := flag.Bool("all-curves", false,
		"offer Go's whole default key-agreement list, the post-quantum hybrid group first (reproduces the silence)")
	flag.Parse()

	if *port == 0 {
		fmt.Fprintln(os.Stderr, "wt-go-client: --port is required")
		os.Exit(2)
	}

	result := run(*host, *port, *path, *message, time.Duration(*timeoutSeconds*float64(time.Second)), allCurves)
	encoded, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wt-go-client: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(encoded))
	if !result.Established || result.ReceivedBytes == 0 {
		os.Exit(1)
	}
}
