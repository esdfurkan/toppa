// toppasvc is the elevated PC service entry (roadmap Step 3). It runs the
// full pipeline as a console process; the Windows-service wrapper (SCM
// integration) is the packaging milestone — run it elevated for now.
//
//	 toppasvc -config toppa.json
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/esdfurkan/toppa/desktop/internal/config"
	"github.com/esdfurkan/toppa/desktop/internal/daemon"
)

func main() {
	cfgPath := flag.String("config", "", "path to config JSON (defaults to built-in defaults)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Println("[toppasvc] starting; routes are journaled and rolled back on exit")
	d, err := daemon.New(cfg)
	if err != nil {
		fatal(err)
	}
	if err := d.Run(ctx); err != nil && ctx.Err() == nil {
		fatal(err)
	}
	fmt.Println("[toppasvc] stopped clean")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "toppasvc:", err)
	os.Exit(1)
}
