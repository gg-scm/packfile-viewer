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
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gg-scm.io/pkg/git/githash"
	"gg-scm.io/pkg/git/packfile/client"
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
	app.router.Handle("/pull", handlers.MethodHandler{
		http.MethodHead: app.newHTMLHandler(app.pullForm),
		http.MethodGet:  app.newHTMLHandler(app.pullForm),
		http.MethodPost: app.newHTMLHandler(app.pull),
	})
	app.router.Handle("/packs/{pack:[-_a-zA-Z0-9]+}", handlers.MethodHandler{
		http.MethodHead: app.newHTMLHandler(app.viewPackfile),
		http.MethodGet:  app.newHTMLHandler(app.viewPackfile),
	})
	app.router.Handle("/app.js", app.newStaticHandler("client/dist/app.js"))
	app.router.Handle("/app.css", app.newStaticHandler("client/dist/app.css"))
}

const packfileExtension = ".pack"

func (app *application) index(ctx context.Context, r *request) (*response, error) {
	var data struct {
		Packfiles []string
	}
	if entries, err := os.ReadDir(app.dir); err != nil && !os.IsNotExist(err) {
		return nil, err
	} else if err == nil {
		for _, ent := range entries {
			if name := ent.Name(); filepath.Ext(name) == packfileExtension {
				data.Packfiles = append(data.Packfiles, strings.TrimSuffix(name, packfileExtension))
			}
		}
	}
	return &response{
		templateName: "index.html",
		data:         data,
	}, nil
}

type pullFormParams struct {
	URL  string
	Refs []*pullFormRef

	URLError  string
	RefsError string
}

type pullFormRef struct {
	*client.Ref
	Selected bool
}

func (app *application) pullForm(ctx context.Context, r *request) (*response, error) {
	data := new(pullFormParams)
	resp := &response{
		templateName: "pull.html",
		data:         data,
	}

	data.URL = r.form.Get("url")
	if data.URL == "" {
		return resp, nil
	}
	u, err := client.ParseURL(data.URL)
	if err != nil {
		data.URLError = err.Error()
		return resp, nil
	}
	remote, err := client.NewRemote(u, nil)
	if err != nil {
		data.URLError = err.Error()
		return resp, nil
	}
	stream, err := remote.StartPull(ctx)
	if err != nil {
		data.URLError = err.Error()
		return resp, nil
	}
	defer stream.Close()
	refs, err := stream.ListRefs()
	if err != nil {
		data.URLError = err.Error()
		return resp, nil
	}
	for _, ref := range refs {
		data.Refs = append(data.Refs, &pullFormRef{
			Ref:      ref,
			Selected: ref.Name == githash.Head,
		})
	}
	return resp, nil
}

func (app *application) pull(ctx context.Context, r *request) (*response, error) {
	data := new(pullFormParams)
	resp := &response{
		templateName: "pull_stream.html",
		stream:       true,
		data:         data,
	}

	data.URL = r.form.Get("url")
	u, err := client.ParseURL(data.URL)
	if err != nil {
		data.URLError = err.Error()
		return resp, nil
	}
	remote, err := client.NewRemote(u, nil)
	if err != nil {
		data.URLError = err.Error()
		return resp, nil
	}
	stream, err := remote.StartPull(ctx)
	if err != nil {
		data.URLError = err.Error()
		return resp, nil
	}
	defer stream.Close()

	refs, err := stream.ListRefs()
	if err != nil {
		data.URLError = err.Error()
		return resp, nil
	}
	for _, ref := range refs {
		selected := false
		for _, refName := range r.form["ref"] {
			if ref.Name.String() == refName {
				selected = true
				break
			}
		}
		data.Refs = append(data.Refs, &pullFormRef{
			Ref:      ref,
			Selected: selected,
		})
	}
	pullRequest := new(client.PullRequest)
requestRefs:
	for _, refName := range r.form["ref"] {
		for _, ref := range data.Refs {
			if ref.Name.String() == refName {
				pullRequest.Want = append(pullRequest.Want, ref.ObjectID)
				continue requestRefs
			}
		}
		data.RefsError = fmt.Sprintf("Unknown ref: %q", refName)
		return resp, nil
	}

	pullResponse, err := stream.Negotiate(pullRequest)
	if err != nil {
		data.URLError = err.Error()
		return resp, nil
	}
	defer pullResponse.Packfile.Close()

	if err := os.MkdirAll(app.dir, 0o777); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(app.dir, "*"+packfileExtension)
	if err != nil {
		return nil, err
	}
	fname := f.Name()
	_, copyErr := io.Copy(f, pullResponse.Packfile)
	closeErr := f.Close()
	if copyErr != nil {
		return nil, copyErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	packName := strings.TrimSuffix(filepath.Base(fname), ".pack")
	return nil, seeOther("/packs/" + packName)
}

func (app *application) viewPackfile(ctx context.Context, r *request) (*response, error) {
	var data struct {
		Name string
	}
	data.Name = r.pathVars["pack"]
	f, err := os.Open(filepath.Join(app.dir, data.Name+packfileExtension))
	if os.IsNotExist(err) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return &response{
		templateName: "packfile.html",
		data:         data,
	}, nil
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
