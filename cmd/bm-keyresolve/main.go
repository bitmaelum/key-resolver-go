// Copyright (c) 2020 BitMaelum Authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package main

import (
	"flag"
	"log"
	net_http "net/http"
	"os"

	"github.com/bitmaelum/key-resolver-go/internal"
	"github.com/bitmaelum/key-resolver-go/internal/handler"
	"github.com/bitmaelum/key-resolver-go/internal/http"
	"github.com/gorilla/mux"
)

// This is a higher order function that encapsulates a given function (f) and makes sure it can function as a regular
// mux handler function. Because we use internally our own request and response objects, we need to convert them first.
// This function makes it a bit easier because we can use in our router simply "requestWrapper(origFunction)"
func requestWrapper(f func(string, http.Request) *http.Response) func(net_http.ResponseWriter, *net_http.Request) {
	return func(w net_http.ResponseWriter, req *net_http.Request) {
		// Convert standard net/http request to our internal request structure
		httpReq := http.NetReqToReq(*req)

		// Fetch hash from mux variables
		hash := mux.Vars(req)["hash"]

		// Call our wrapped function
		var resp = f(hash, httpReq)

		// Write response to output
		w.WriteHeader(resp.StatusCode)
		for k, v := range resp.Headers {
			// @TODO: we are only setting the first value
			w.Header().Set(k, v[0])
		}
		_, _ = w.Write([]byte(resp.Body))
	}
}

func getLogo(_ string, _ http.Request) *http.Response {
	headers := map[string][]string{}
	headers["Content-Type"] = []string{"application/json"}

	return &http.Response{
		StatusCode: 200,
		Headers:    headers,
		Body:       internal.Logo,
	}
}

func main() {
	boltDbPath := flag.String("db", "./bolt.db", "Bolt DB path")
	TcpPort := flag.String("port", "443", "HTTP(s) port to run")
	ServeHttp := flag.Bool("http", false, "Run in HTTP mode")
	CertPemFile := flag.String("cert", "./cert.pem", "Cert file in PEM format")
	KeyPemFile := flag.String("key", "./key.pem", "Key file in PEM format")
	flag.Parse()

	// Make sure we use BOLTDB
	_ = os.Setenv("USE_BOLT", "1")
	_ = os.Setenv("BOLT_DB_FILE", *boltDbPath)

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", requestWrapper(getLogo)).Methods("GET")

	router.HandleFunc("/address/{hash}", requestWrapper(handler.GetAddressHash)).Methods("GET")
	router.HandleFunc("/address/{hash}", requestWrapper(handler.DeleteAddressHash)).Methods("DELETE")
	router.HandleFunc("/address/{hash}", requestWrapper(handler.PostAddressHash)).Methods("POST")

	router.HandleFunc("/routing/{hash}", requestWrapper(handler.GetRoutingHash)).Methods("GET")
	router.HandleFunc("/routing/{hash}", requestWrapper(handler.DeleteRoutingHash)).Methods("DELETE")
	router.HandleFunc("/routing/{hash}", requestWrapper(handler.PostRoutingHash)).Methods("POST")

	router.HandleFunc("/organisation/{hash}", requestWrapper(handler.GetOrganisationHash)).Methods("GET")
	router.HandleFunc("/organisation/{hash}", requestWrapper(handler.DeleteOrganisationHash)).Methods("DELETE")
	router.HandleFunc("/organisation/{hash}", requestWrapper(handler.PostOrganisationHash)).Methods("POST")

	// Serve HTTP if we like
	if *ServeHttp {
		err := net_http.ListenAndServe(":"+*TcpPort, router)
		log.Fatal(err)
	}

	err := net_http.ListenAndServeTLS(":"+*TcpPort, *CertPemFile, *KeyPemFile, router)
	log.Fatal(err)
}
