package main

import (
	"crypto/tls"
	"flag"
	"io"
	"net/http"
	"net/url"

	"github.com/tidwall/gjson"
)

func main() {

	userAgent := flag.String("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36", "User-Agent")
	origin := flag.String("origin", "", "Origin")
	referer := flag.String("referer", "", "Referer")

	path := flag.String("path", "", "GJSON Path (https://github.com/tidwall/gjson/blob/master/SYNTAX.md)")

	flag.Parse()

	if len(flag.Args()) == 0 {
		panic("Please provide a URL")
	}

	u, err := url.Parse(flag.Args()[0])
	if err != nil {
		panic(err)
	}

	if *origin == "" {
		*origin = u.Scheme + "://" + u.Host
	}

	if *referer == "" {
		*referer = u.String()
	}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic(err)
	}

	req.Header.Set("User-Agent", *userAgent)
	req.Header.Set("Origin", *origin)
	req.Header.Set("Referer", *referer)

	// Prevent Cloudflare detection
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				},
				ServerName: u.Host,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	if *path == "" {
		println(string(body))
	} else {
		result := gjson.Get(string(body), *path).String()
		println(result)
	}

}
