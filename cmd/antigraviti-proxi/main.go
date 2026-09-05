package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/app"
	"github.com/Homiakus/AntigravitiProxi/internal/platform"
	"github.com/Homiakus/AntigravitiProxi/internal/proxy"
)

var version = "dev"

func main() {
	// Internal fixed-function privilege entry point. It is intentionally not a
	// general command runner and is invoked only through the OS privilege broker
	// by the ordinary-user control plane.
	if len(os.Args) > 1 && os.Args[1] == "__linux-privileged-setup" {
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "invalid privileged setup invocation")
			os.Exit(2)
		}
		if err := proxy.RunLinuxPrivilegedSetup(os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	noBrowser := flag.Bool("no-browser", false, "do not open the web UI automatically")
	printVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *printVersion {
		fmt.Println("AntigravitiProxi", version)
		return
	}
	srv, err := app.New()
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if err := srv.Close(ctx); err != nil {
			log.Printf("network helper shutdown: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	url := "http://" + srv.ListenAddr() + "/"
	log.Printf("AntigravitiProxi %s", version)
	log.Printf("data: %s", srv.Root())
	log.Printf("web UI: %s", url)
	if srv.AutoOpen() && !(*noBrowser) {
		go func() {
			time.Sleep(450 * time.Millisecond)
			if e := platform.OpenBrowser(url); e != nil {
				log.Printf("open browser: %v", e)
			}
		}()
	}
	err = srv.Serve(ctx)
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
