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
)

var version = "dev"

func main() {
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
