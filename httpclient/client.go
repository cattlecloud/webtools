package httpclient

import (
	"net"
	"net/http"
	"time"
)

func pooledTransport() *http.Transport {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 3 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   1,
	}
	return transport
}

var client = &http.Client{
	Timeout:   1 * time.Minute,
	Transport: pooledTransport(),
}

// Get returns an http.Client tuned for shared / pooled connections, with
// reasonable values for idle connections, timeouts, and http2 usage.
func Get() *http.Client {
	return client
}
