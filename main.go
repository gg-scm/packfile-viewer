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
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gg-scm.io/pkg/git/githash"
	"gg-scm.io/pkg/git/object"
	"gg-scm.io/pkg/git/packfile"
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
	app.router = mux.NewRouter().StrictSlash(true)
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
	app.router.Handle("/packs/{pack:[-_a-zA-Z0-9]+}/objects/", handlers.MethodHandler{
		http.MethodHead: app.newHTMLHandler(app.packfileObjects),
		http.MethodGet:  app.newHTMLHandler(app.packfileObjects),
	})
	app.router.Handle("/packs/{pack:[-_a-zA-Z0-9]+}/objects/{object:[a-fA-F0-9]+}", handlers.MethodHandler{
		http.MethodHead: app.newHTMLHandler(app.viewObject),
		http.MethodGet:  app.newHTMLHandler(app.viewObject),
	})
	app.router.Handle("/packs/{pack:[-_a-zA-Z0-9]+}/objects/raw/{object:[a-fA-F0-9]+}", handlers.MethodHandler{
		http.MethodHead: http.HandlerFunc(app.downloadObject),
		http.MethodGet:  http.HandlerFunc(app.downloadObject),
	})

	app.router.Handle("/app.js", app.newStaticHandler("client/dist/app.js"))
	app.router.Handle("/app.css", app.newStaticHandler("client/dist/app.css"))
}

const (
	packfileExtension  = ".pack"
	packIndexExtension = ".idx"
	packInfoExtension  = ".json"
)

type packInfo struct {
	Name string `json:"-"`
	Size int64  `json:"-"`

	URL      string                       `json:"url"`
	PullTime time.Time                    `json:"time"`
	Refs     map[githash.Ref]githash.SHA1 `json:"refs,omitempty"`
}

func (app *application) index(ctx context.Context, r *request) (*response, error) {
	var data struct {
		Packfiles []*packInfo
	}
	if entries, err := os.ReadDir(app.dir); err != nil && !os.IsNotExist(err) {
		return nil, err
	} else if err == nil {
		for _, ent := range entries {
			if name := ent.Name(); filepath.Ext(name) != packfileExtension {
				continue
			}
			name := strings.TrimSuffix(ent.Name(), packfileExtension)
			data.Packfiles = append(data.Packfiles, app.getPackInfo(ctx, name))
		}
	}
	sort.Slice(data.Packfiles, func(i, j int) bool {
		return data.Packfiles[i].PullTime.After(data.Packfiles[j].PullTime)
	})
	return &response{
		templateName: "index.html",
		data:         data,
	}, nil
}

func (app *application) getPackInfo(ctx context.Context, name string) *packInfo {
	info := &packInfo{Name: name}
	packPath := filepath.Join(app.dir, name+packfileExtension)
	if stat, err := os.Stat(packPath); err != nil {
		log.Warnf(ctx, "Getting info for %s: %v", name, err)
	} else {
		info.PullTime = stat.ModTime()
		info.Size = stat.Size()
	}
	infoPath := filepath.Join(app.dir, info.Name+packInfoExtension)
	if infoData, err := ioutil.ReadFile(infoPath); err != nil && !os.IsNotExist(err) {
		log.Warnf(ctx, "Getting info for %s: %v", name, err)
	} else if err == nil {
		if err := json.Unmarshal(infoData, &info); err != nil {
			log.Warnf(ctx, "Getting info for %s: %v", name, err)
		}
	}
	return info
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
	_, remote, err := newRemote(data.URL)
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
	u, remote, err := newRemote(data.URL)
	if err != nil {
		data.URLError = err.Error()
		return resp, nil
	}
	selectedRefs := make(map[string]struct{})
	for _, r := range r.form["ref"] {
		selectedRefs[r] = struct{}{}
	}
	if len(selectedRefs) == 0 {
		data.RefsError = "No refs selected."
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
	info := &packInfo{
		URL:  data.URL,
		Refs: make(map[githash.Ref]githash.SHA1, len(selectedRefs)),
	}
	pullRequest := new(client.PullRequest)
	for _, ref := range refs {
		_, selected := selectedRefs[ref.Name.String()]
		data.Refs = append(data.Refs, &pullFormRef{
			Ref:      ref,
			Selected: selected,
		})
		if selected {
			info.Refs[ref.Name] = ref.ObjectID
			pullRequest.Want = append(pullRequest.Want, ref.ObjectID)
		}
	}
requestRefs:
	for refName := range selectedRefs {
		for _, ref := range data.Refs {
			if ref.Name.String() == refName {
				continue requestRefs
			}
		}
		data.RefsError = fmt.Sprintf("Unknown ref: %q", refName)
		return resp, nil
	}

	info.PullTime = time.Now()
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
	size, err := io.Copy(f, pullResponse.Packfile)
	if err != nil {
		f.Close()
		os.Remove(fname)
		return nil, err
	}
	packName := strings.TrimSuffix(filepath.Base(fname), packfileExtension)
	if _, err := app.ensureIndex(ctx, packName, f, size); err != nil {
		f.Close()
		os.Remove(fname)
		return nil, err
	}
	err = f.Close()
	if err != nil {
		os.Remove(fname)
		return nil, err
	}
	if infoData, err := json.Marshal(info); err != nil {
		log.Warnf(ctx, "Save packfile info for %s (%s): %v", packName, u.Redacted(), err)
	} else {
		infoPath := filepath.Join(app.dir, packName+packInfoExtension)
		if err := ioutil.WriteFile(infoPath, infoData, 0o666); err != nil {
			log.Warnf(ctx, "Save packfile info for %s (%s): %v", packName, u.Redacted(), err)
		}
	}
	return nil, seeOther("/packs/" + packName)
}

func newRemote(urlstr string) (*url.URL, *client.Remote, error) {
	u, err := client.ParseURL(strings.TrimSpace(urlstr))
	if err != nil {
		return nil, nil, err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, nil, fmt.Errorf("only http and https URLs allowed")
	}
	remote, err := client.NewRemote(u, nil)
	if err != nil {
		return nil, nil, err
	}
	return u, remote, nil
}

func (app *application) viewPackfile(ctx context.Context, r *request) (*response, error) {
	var data struct {
		packInfo
	}
	data.Name = r.pathVars["pack"]
	if _, err := os.Stat(filepath.Join(app.dir, data.Name+packfileExtension)); os.IsNotExist(err) {
		return nil, errNotFound
	}
	data.packInfo = *app.getPackInfo(ctx, data.Name) // fills in data.Size
	return &response{
		templateName: "packfile.html",
		data:         data,
	}, nil
}

func (app *application) packfileObjects(ctx context.Context, r *request) (*response, error) {
	type objectHeader struct {
		Offset           int64
		DecompressedSize int64
		Type             object.Type
		ID               githash.SHA1
		PackType         packfile.ObjectType
	}
	var data struct {
		packInfo
		Objects     []objectHeader
		RefDelta    packfile.ObjectType
		OffsetDelta packfile.ObjectType

		PrevAfter int64
		NextAfter int64
	}
	data.Name = r.pathVars["pack"]
	after, _ := strconv.ParseInt(r.form.Get("after"), 10, 64)
	data.RefDelta = packfile.RefDelta
	data.OffsetDelta = packfile.OffsetDelta

	f, err := os.Open(filepath.Join(app.dir, data.Name+packfileExtension))
	if os.IsNotExist(err) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data.packInfo = *app.getPackInfo(ctx, data.Name) // fills in data.Size
	idx, err := app.ensureIndex(ctx, data.Name, f, data.Size)
	if err != nil {
		return nil, err
	}
	data.Objects = make([]objectHeader, 0, len(idx.Offsets))
	bf := packfile.NewBufferedReadSeeker(f)
	for i, off := range idx.Offsets {
		data.Objects = append(data.Objects, objectHeader{
			Offset: off,
			ID:     idx.ObjectIDs[i],
		})
	}
	sort.Slice(data.Objects, func(i, j int) bool {
		return data.Objects[i].Offset < data.Objects[j].Offset
	})
	startPos := sort.Search(len(data.Objects), func(i int) bool {
		return data.Objects[i].Offset > after
	})
	const objectsPerPage = 50
	if startPos == 0 {
		data.PrevAfter = -1
	} else if startPos > objectsPerPage {
		data.PrevAfter = data.Objects[startPos-objectsPerPage-1].Offset
	}
	data.Objects = data.Objects[startPos:]
	if len(data.Objects) > objectsPerPage {
		data.Objects = data.Objects[:objectsPerPage]
		data.NextAfter = data.Objects[objectsPerPage-1].Offset
	}
	for i := range data.Objects {
		hdr := &data.Objects[i]
		if _, err := bf.Seek(hdr.Offset, io.SeekStart); err == nil {
			if diskHdr, _ := packfile.ReadHeader(hdr.Offset, bf); diskHdr != nil {
				hdr.PackType = diskHdr.Type
				hdr.DecompressedSize = diskHdr.Size
				hdr.Type = diskHdr.Type.NonDelta()
			}
			if hdr.Type == "" {
				hdr.Type, _ = packfile.ResolveType(bf, hdr.Offset, &packfile.UndeltifyOptions{
					Index: idx,
				})
			}
		}
	}
	return &response{
		templateName: "packfile_objects.html",
		data:         data,
	}, nil
}

func (app *application) ensureIndex(ctx context.Context, name string, f io.ReaderAt, fileSize int64) (*packfile.Index, error) {
	idxFilename := filepath.Join(app.dir, name+packIndexExtension)
	idxFile, err := os.OpenFile(idxFilename, os.O_RDWR|os.O_CREATE, 0o666)
	if err != nil {
		return nil, err
	}
	defer idxFile.Close()
	if stat, err := idxFile.Stat(); err == nil && stat.Size() > 0 {
		// File already has data: read the index from it.
		return packfile.ReadIndex(idxFile)
	}
	idx, err := packfile.BuildIndex(f, fileSize)
	if err != nil {
		return nil, err
	}
	encodeErr := idx.EncodeV2(idxFile)
	closeErr := idxFile.Close()
	if encodeErr != nil {
		log.Warnf(ctx, "Saving %s index: %v", name, encodeErr)
	}
	if closeErr != nil {
		log.Warnf(ctx, "Saving %s index: %v", name, closeErr)
	}
	if encodeErr != nil || closeErr != nil {
		if rmErr := os.Remove(idxFilename); rmErr != nil {
			log.Warnf(ctx, "Could not clean up failed index: %v", rmErr)
		}
	}
	return idx, nil
}

func (app *application) viewObject(ctx context.Context, r *request) (*response, error) {
	var data struct {
		Pack     *packInfo
		ObjectID githash.SHA1

		object.Prefix
		Tree      object.Tree
		Commit    *object.Commit
		Tag       *object.Tag
		Raw       []byte
		MediaType string
		TooBig    bool
	}
	packName := r.pathVars["pack"]
	data.Pack = app.getPackInfo(ctx, packName)
	var err error
	data.ObjectID, err = githash.ParseSHA1(r.pathVars["object"])
	if err != nil {
		return nil, errNotFound
	}
	f, err := os.Open(filepath.Join(app.dir, packName+packfileExtension))
	if os.IsNotExist(err) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	idx, err := app.ensureIndex(ctx, packName, f, info.Size())
	if err != nil {
		return nil, err
	}
	i := idx.FindID(data.ObjectID)
	if i == -1 {
		return nil, errNotFound
	}
	bf := packfile.NewBufferedReadSeeker(f)
	var content io.Reader
	data.Prefix, content, err = new(packfile.Undeltifier).Undeltify(bf, idx.Offsets[i], &packfile.UndeltifyOptions{
		Index: idx,
	})
	if err != nil {
		return nil, err
	}
	contentType, content := sniff(content)
	data.MediaType, _, _ = mime.ParseMediaType(contentType)
	const rawLimit = 100 << 10 // 100 KiB
	if data.Size > rawLimit {
		data.Raw = nil
		data.TooBig = true
	} else {
		data.Raw, err = ioutil.ReadAll(io.LimitReader(content, data.Size))
		if err != nil {
			return nil, err
		}
		switch data.Type {
		case object.TypeTree:
			data.Tree, _ = object.ParseTree(data.Raw)
		case object.TypeCommit:
			data.Commit, _ = object.ParseCommit(data.Raw)
		case object.TypeTag:
			data.Tag, _ = object.ParseTag(data.Raw)
		}
	}
	return &response{
		templateName: "object.html",
		data:         data,
	}, nil
}

func (app *application) downloadObject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pathVars := mux.Vars(r)
	packName := pathVars["pack"]
	var err error
	objectID, err := githash.ParseSHA1(pathVars["object"])
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(app.dir, packName+packfileExtension))
	if os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}
	respondError := func(err error) {
		log.Errorf(ctx, "Download object %v from %s: %v", objectID, packName, err)
		http.Error(w, "There was a problem downloading the object. Check the server logs.", http.StatusInternalServerError)
	}
	if err != nil {
		respondError(err)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		respondError(err)
		return
	}
	idx, err := app.ensureIndex(ctx, packName, f, info.Size())
	if err != nil {
		respondError(err)
		return
	}
	i := idx.FindID(objectID)
	if i == -1 {
		http.NotFound(w, r)
		return
	}
	etagValue := `"` + objectID.String() + `"`
	for _, part := range strings.Split(r.Header.Get("If-None-Match"), ",") {
		if strings.TrimSpace(part) == etagValue {
			w.Header().Set("ETag", etagValue)
			w.Header().Set("Cache-Control", "immutable")
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	bf := packfile.NewBufferedReadSeeker(f)
	prefix, content, err := new(packfile.Undeltifier).Undeltify(bf, idx.Offsets[i], &packfile.UndeltifyOptions{
		Index: idx,
	})
	if err != nil {
		respondError(err)
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(prefix.Size, 10))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	contentType := "application/octet-stream"
	switch prefix.Type {
	case object.TypeCommit, object.TypeTag:
		// Both of these are safe to transmit as text.
		contentType = "text/plain; charset=utf-8"
	case object.TypeBlob:
		contentType, content = sniff(content)
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "immutable")
	w.Header().Set("ETag", etagValue)
	if r.Method != http.MethodHead {
		io.Copy(w, content)
	}
}

const binaryMediaType = "application/octet-stream"

func sniff(r io.Reader) (string, io.Reader) {
	buf := make([]byte, 512)
	n, _ := io.ReadFull(r, buf)
	buf = buf[:n]
	sniffedContentType := http.DetectContentType(buf)
	// MIME types that we permit to serve. Importantly, we don't want to serve
	// anything that can be interpreted as HTML or a webpage resource
	// (e.g. CSS, JavaScript).
	allowed := map[string]struct{}{
		"application/ogg":              {},
		"application/pdf":              {},
		"application/postscript":       {},
		"application/x-gzip":           {},
		"application/x-rar-compressed": {},
		"application/zip":              {},
		"audio/aiff":                   {},
		"audio/basic":                  {},
		"audio/midi":                   {},
		"audio/mpeg":                   {},
		"audio/wave":                   {},
		"image/bmp":                    {},
		"image/gif":                    {},
		"image/jpeg":                   {},
		"image/png":                    {},
		"image/webp":                   {},
		"image/x-icon":                 {},
		"text/plain":                   {},
		"video/avi":                    {},
		"video/mp4":                    {},
		"video/webm":                   {},
	}
	contentType := binaryMediaType
	if mt, _, err := mime.ParseMediaType(sniffedContentType); err == nil {
		if _, ok := allowed[mt]; ok {
			contentType = sniffedContentType
		}
	}
	return contentType, io.MultiReader(bytes.NewReader(buf), r)
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
