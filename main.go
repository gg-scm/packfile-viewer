// Copyright 2021 The gg Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//		 https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"golang.org/x/sys/unix"
	"zombiezen.com/go/log"
)

//go:embed templates
//go:embed client/dist
var files embed.FS

type application struct {
	dir   string
	files fs.FS

	routerOnce sync.Once
	router     *mux.Router
}

func (app *application) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	app.routerOnce.Do(app.initRouter)
	app.router.ServeHTTP(w, r)
}

func (app *application) initRouter() {
	app.router = mux.NewRouter()
	app.router.Handle("/", handlers.MethodHandler{
		http.MethodHead: app.newHTMLHandler(app.index),
		http.MethodGet:  app.newHTMLHandler(app.index),
	})
	app.router.Handle("/app.js", handlers.MethodHandler{
		http.MethodHead: app.newStaticHandler("client/dist/app.js"),
		http.MethodGet:  app.newStaticHandler("client/dist/app.js"),
	})
	app.router.Handle("/app.css", handlers.MethodHandler{
		http.MethodHead: app.newStaticHandler("client/dist/app.css"),
		http.MethodGet:  app.newStaticHandler("client/dist/app.css"),
	})
}

func (app *application) index(ctx context.Context, r *request) (*response, error) {
	return &response{templateName: "index.html"}, nil
}

func main() {
	app := &application{
		files: files,
	}
	flag.StringVar(&app.dir, "dir", "packs", "directory to store packfiles in")
	resourcePath := flag.String("resources", "", "path to resources (default is to use embedded resources)")
	showDebug := flag.Bool("debug", false, "show debugging output")
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(64)
	}
	minLogLevel := log.Info
	if *showDebug {
		minLogLevel = log.Debug
	}
	log.SetDefault(&log.LevelFilter{
		Min:    minLogLevel,
		Output: log.New(os.Stderr, "packfile-viewer: ", log.StdFlags, nil),
	})
	ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGTERM)
	defer cancel()

	if *resourcePath != "" {
		app.files = os.DirFS(*resourcePath)
	}

	portString := os.Getenv("PORT")
	if portString == "" {
		portString = "8080"
	}
	port, err := net.Listen("tcp", ":"+portString)
	if err != nil {
		log.Errorf(ctx, "%v", err)
		os.Exit(1)
	}
	log.Infof(ctx, "Listening on http://localhost:%d/", port.Addr().(*net.TCPAddr).Port)

	srv := &http.Server{
		Handler:           app,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	idleConnsClosed := make(chan struct{})
	go func() {
		defer close(idleConnsClosed)
		<-ctx.Done()
		log.Infof(ctx, "Shutting down...")
		if err := srv.Shutdown(context.Background()); err != nil {
			log.Errorf(ctx, "During shutdown: %v", err)
		}
	}()
	exitCode := 0
	if err := srv.Serve(port); !errors.Is(err, http.ErrServerClosed) {
		log.Errorf(ctx, "%v", err)
		exitCode = 1
	}
	<-idleConnsClosed
	os.Exit(exitCode)
}
