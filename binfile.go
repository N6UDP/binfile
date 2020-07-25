package main

// Fair bit taken from https://github.com/kjk/go-cookbook/blob/master/free-ssl-certificates/main.go (public domain)
// To run:
// go run main.go
// Command-line options:
//   -production : enables HTTPS on port 443

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"

	//	"time"

	"github.com/c2h5oh/datasize"
	"golang.org/x/crypto/acme/autocert"
)

const (
	htmlIndex = `<!DOCTYPE html>
<html>
	<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>binfile</title>
	<style type="text/css">body{margin:40px auto;max-width:650px;line-height:1.6;font-size:18px;color:#444;padding:0 10px}h1,h2,h3{line-height:1.2}</style>
</head>
<body>
<h1>Welcome to a binfile server!</h1>
<h2>/#size# will return file of that size e.g. /100mb made up entirely of 0xAA!</h2>
<h2>/rand/#size# will return a pseudo random file (a repeated 9000 byte random chunk) of that size e.g. /rand/100mb!</h2>
<p>Source lives <a href="https://github.com/n6udp/binfile">here</a>
</body>
</html>`
)

const (
	fixed    byte   = 170
	buffsize uint64 = 9000
)

var (
	httpPort    = ""
	httpsPort   = ""
	allowedHost = ""
)

func handleIndex(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request index %q", r.URL.Path)
	if len(r.URL.Path) > 1 {
		handleDataRequest(w, r, false, 1)
	} else {
		io.WriteString(w, htmlIndex)
	}
}

func handleRng(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request rng %q", r.URL.Path)
	handleDataRequest(w, r, true, 6)
}

func handleDataRequest(w http.ResponseWriter, r *http.Request, rng bool, pathlength int) {
	var datalength datasize.ByteSize
	err := datalength.UnmarshalText([]byte(r.URL.Path[pathlength:len(r.URL.Path)]))
	if err != nil {
		io.WriteString(w, "Invalid Request")
		log.Printf("Failed to get bytesize %s", err)
		return
	}
	log.Printf("Returning %d bytes", datalength)
	w.Header().Set("Content-Type", "application/binary")
	buf := make([]byte, buffsize)
	if rng {
		rand.Read(buf)
	} else {
		for i := 0; i < len(buf); i++ {
			buf[i] = fixed
		}
	}
	datalengthint64 := datalength.Bytes()
	for ; datalengthint64 > buffsize; datalengthint64 -= buffsize {
		w.Write(buf)
	}
	w.Write(buf[0:datalengthint64])
}

func makeServerFromMux(mux *http.ServeMux) *http.Server {
	// set timeouts so that a slow or malicious client doesn't
	// hold resources forever
	return &http.Server{
		//ReadTimeout:  5 * time.Second,
		//WriteTimeout: 5 * time.Second,
		//IdleTimeout:  120 * time.Second,
		Handler: mux,
	}
}

func makeHTTPServer() *http.Server {
	mux := &http.ServeMux{}
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/rand/", handleRng)
	return makeServerFromMux(mux)

}

func parseFlags() {
	flag.StringVar(&allowedHost, "httpshostname", "www.example.com", "hostname for acme for https")
	flag.StringVar(&httpsPort, "httpsbindaddr", "0.0.0.0:443", "ip:port combo for https")
	flag.StringVar(&httpPort, "httpbindaddr", "127.0.0.1:8080", "ip:port combo for http")
	flag.Parse()
}

func main() {
	parseFlags()
	var m *autocert.Manager

	var httpsSrv *http.Server
	if allowedHost != "www.example.com" {
		hostPolicy := func(ctx context.Context, host string) error {
			if host == allowedHost {
				return nil
			}
			return fmt.Errorf("acme/autocert: only %s host is allowed", allowedHost)
		}

		dataDir := "."
		m = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: hostPolicy,
			Cache:      autocert.DirCache(dataDir),
		}

		httpsSrv = makeHTTPServer()
		httpsSrv.Addr = httpsPort
		httpsSrv.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate}

		go func() {
			log.Printf("Starting HTTPS server on %s\n", httpsSrv.Addr)
			err := httpsSrv.ListenAndServeTLS("", "")
			if err != nil {
				log.Fatalf("httpsSrv.ListendAndServeTLS() failed with %s", err)
			}
		}()
	}

	var httpSrv *http.Server
	httpSrv = makeHTTPServer()
	// allow autocert handle Let's Encrypt callbacks over http
	if m != nil {
		httpSrv.Handler = m.HTTPHandler(httpSrv.Handler)
	}

	httpSrv.Addr = httpPort
	log.Printf("Starting HTTP server on %s\n", httpPort)
	err := httpSrv.ListenAndServe()
	if err != nil {
		log.Fatalf("httpSrv.ListenAndServe() failed with %s", err)
	}
}
