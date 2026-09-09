// Package api exposes the local control plane for the Fyne tray/CLI
// (architecture §3.1): loopback-only HTTP with /status and /reconnect.
// Named-pipe + gRPC is the documented Step 5+ upgrade; loopback HTTP keeps
// the tray testable with stdlib and binds to 127.0.0.1 only.
package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Status is the daemon's public health snapshot.
type Status struct {
	State     string `json:"state"` // online | connecting | offline
	Transport string `json:"transport"`
	Since     time.Time `json:"since"`
}

// Control is the daemon-side implementation surface.
type Control interface {
	Status() Status
	Reconnect()
}

// Server serves the control API on a loopback address.
type Server struct {
	control Control
	srv     *http.Server
}

func NewServer(addr string, control Control) *Server {
	mux := http.NewServeMux()
	s := &Server{control: control, srv: &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 2 * time.Second}}

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.control.Status())
	})
	mux.HandleFunc("/reconnect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		s.control.Reconnect()
		fmt.Fprintln(w, "ok")
	})
	return s
}

// Listen binds loopback and serves in a background goroutine.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return fmt.Errorf("api: listen %s: %w", s.srv.Addr, err)
	}
	go func() { _ = s.srv.Serve(ln) }()
	return nil
}

func (s *Server) Close() { _ = s.srv.Close() }
