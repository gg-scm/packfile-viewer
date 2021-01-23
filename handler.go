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
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"zombiezen.com/go/log"
)

type request struct {
	pathVars map[string]string
}

type response struct {
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

func (h htmlHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	resp, err := h.f(ctx, &request{
		pathVars: mux.Vars(r),
	})
	const genericMessage = "Error while serving page. Check server logs."
	if err != nil {
		log.Errorf(ctx, "%s: %v", r.URL.Path, err)
		http.Error(w, genericMessage, http.StatusInternalServerError)
		return
	}

	const baseName = "base.html"
	t, err := template.ParseFS(h.files, "templates/"+baseName, "templates/"+resp.templateName)
	if err != nil {
		// Fine to expose error to client, since templates are trusted and not based
		// on user input.
		log.Errorf(ctx, "Render %s: %v", r.URL.Path, err)
		http.Error(w, "Templates failed to parse: "+err.Error(), http.StatusInternalServerError)
		return
	}
	buf := new(bytes.Buffer)
	if err := t.ExecuteTemplate(buf, baseName, resp.data); err != nil {
		log.Errorf(ctx, "Render %s: %v", r.URL.Path, err)
		http.Error(w, genericMessage, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	if r.Method != http.MethodHead {
		io.Copy(w, buf)
	}
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
