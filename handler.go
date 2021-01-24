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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"zombiezen.com/go/bass/accept"
	"zombiezen.com/go/log"
)

type request struct {
	pathVars            map[string]string
	form                url.Values
	supportsTurboStream bool
}

type response struct {
	stream       bool
	templateName string
	data         interface{}
}

type htmlHandler struct {
	files fs.FS
	f     func(context.Context, *request) (*response, error)
}

func (app *application) newHTMLHandler(f func(context.Context, *request) (*response, error)) htmlHandler {
	return htmlHandler{app.files, f}
}

const (
	htmlContentType        = "text/html"
	turboStreamContentType = "text/vnd.turbo-stream.html"

	utf8Params = "; charset=utf-8"
)

func (h htmlHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.ParseForm()
	if err := r.ParseMultipartForm(1 << 20 /* 1 MiB */); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		http.Error(w, "Invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	if r.MultipartForm != nil {
		// Don't need to keep any files for now, so removing.
		if err := r.MultipartForm.RemoveAll(); err != nil {
			log.Warnf(ctx, "Cleaning up multipart form data: %v", err)
		}
	}
	accept, err := accept.ParseHeader(r.Header.Get("Accept"))
	if err != nil {
		http.Error(w, "Invalid Accept header: "+err.Error(), http.StatusBadRequest)
		return
	}

	req := &request{
		pathVars: mux.Vars(r),
		form:     r.Form,
	}
	turboStreamQuality := accept.Quality(turboStreamContentType, map[string][]string{
		"charset": {"utf-8"},
	})
	if turboStreamQuality > 0 {
		req.supportsTurboStream = true
	}
	resp, err := h.f(ctx, req)
	if errors.Is(err, errNotFound) {
		// TODO(someday): Render 404.html
		http.NotFound(w, r)
		return
	}
	if redirect := (*redirectError)(nil); errors.As(err, &redirect) {
		http.Redirect(w, r, redirect.location, redirect.statusCode)
		return
	}
	const genericMessage = "Error while serving page. Check server logs."
	if err != nil {
		log.Errorf(ctx, "%s: %v", r.URL.Path, err)
		http.Error(w, genericMessage, http.StatusInternalServerError)
		return
	}

	funcMap := template.FuncMap{
		"byteSize": func(v reflect.Value) (string, error) {
			var f float64
			switch v.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				f = float64(v.Int())
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				f = float64(v.Uint())
			default:
				return "", fmt.Errorf("type is %v instead of int-like", v.Type())
			}
			if f < 1024 {
				return fmt.Sprintf("%d B", int(f)), nil
			}
			f /= 1024
			if f < 1024 {
				return fmt.Sprintf("%.1f KiB", f), nil
			}
			f /= 1024
			if f < 1024 {
				return fmt.Sprintf("%.1f MiB", f), nil
			}
			return fmt.Sprintf("%.1f GiB", f), nil
		},
	}
	var contentType string
	var t *template.Template
	if resp.stream {
		contentType = turboStreamContentType + utf8Params
		t = template.New(resp.templateName)
		t.Funcs(funcMap)
	} else {
		contentType = htmlContentType + utf8Params
		t = template.New("base.html")
		t.Funcs(funcMap)
		if _, err := t.ParseFS(h.files, "templates/base.html"); err != nil {
			log.Errorf(ctx, "Render %s: %v", r.URL.Path, err)
			http.Error(w, "Templates failed to parse: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	t, err = t.ParseFS(h.files,
		"templates/"+resp.templateName,
		"templates/partials/*.html",
	)
	if err != nil {
		// Fine to expose error to client, since templates are trusted and not based
		// on user input.
		log.Errorf(ctx, "Render %s: %v", r.URL.Path, err)
		http.Error(w, "Templates failed to parse: "+err.Error(), http.StatusInternalServerError)
		return
	}
	buf := new(bytes.Buffer)
	if err := t.Execute(buf, resp.data); err != nil {
		log.Errorf(ctx, "Render %s: %v", r.URL.Path, err)
		http.Error(w, genericMessage, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	if r.Method != http.MethodHead {
		io.Copy(w, buf)
	}
}

var errNotFound = errors.New("not found")

type redirectError struct {
	statusCode int
	location   string
}

func seeOther(location string) *redirectError {
	return &redirectError{
		statusCode: http.StatusSeeOther,
		location:   location,
	}
}

func (e *redirectError) Error() string {
	return fmt.Sprintf("http %d (%s) redirect to %s",
		e.statusCode, http.StatusText(e.statusCode), e.location)
}

type staticFileHandler struct {
	files fs.FS
	name  string
}

func (app *application) newStaticHandler(name string) staticFileHandler {
	return staticFileHandler{app.files, name}
}

func (h staticFileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "Only GET and HEAD allowed on resource", http.StatusMethodNotAllowed)
		return
	}
	data, err := fs.ReadFile(h.files, h.name)
	if errors.Is(err, fs.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Errorf(ctx, "Could not serve static file: %v", err)
		http.Error(w, "Error serving file. Check the error logs.", http.StatusInternalServerError)
		return
	}
	sum := sha256.Sum256(data)
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
	http.ServeContent(w, r, h.name, time.Time{}, bytes.NewReader(data))
}
