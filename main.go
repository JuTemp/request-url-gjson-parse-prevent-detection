package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tidwall/gjson"
)

func main() {

	userAgent := flag.String("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36", "User-Agent")
	origin := flag.String("origin", "", "Origin")
	referer := flag.String("referer", "", "Referer")
	cookie := flag.String("cookie", "", "Cookie")
	authorization := flag.String("authorization", "", "Authorization")
	contentType := flag.String("content-type", "", "Content-Type")
	dataRaw := flag.String("data-raw", "", "Raw Data")

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

	var method string
	var reqBody io.Reader
	if *dataRaw != "" {
		method = "POST"
		reqBody = strings.NewReader(*dataRaw)
	} else {
		method = "GET"
		reqBody = nil
	}

	req, err := http.NewRequest(method, u.String(), reqBody)
	if err != nil {
		panic(err)
	}

	for k, v := range map[string]string{
		"User-Agent":    *userAgent,
		"Origin":        *origin,
		"Referer":       *referer,
		"Cookie":        *cookie,
		"Authorization": *authorization,
		"Content-Type":  *contentType,
	} {
		if v != "" {
			req.Header.Set(k, v)
		}
	}

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
		fmt.Println(string(body))
	} else {
		result := gjson.Get(string(body), *path).String()
		fmt.Println(result)
	}

}
