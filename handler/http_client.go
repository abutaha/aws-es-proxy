package handler

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/abutaha/aws-es-proxy/config"
	"github.com/spf13/viper"
)

// NewHTTPClient -
func NewHTTPClient() *http.Client {
	var (
		conf                  *viper.Viper
		timeout               time.Duration
		insecureSSL           bool
		idleConnTimeout       time.Duration
		tlsHandshakeTimeout   time.Duration
		expectContinueTimeout time.Duration
		dialTimeout           time.Duration
		keepAlive             time.Duration
		dialer                *net.Dialer
		transport             *http.Transport
		client                *http.Client
	)

	// Read from config.yaml file
	conf = config.CFG

	// Global timout
	timeout = conf.GetDuration("global.request_timeout")

	// Accept insecure SSL certificates
	insecureSSL = conf.GetBool("global.accept_insecure_ssl")

	// Low level http transport timeouts.
	idleConnTimeout = conf.GetDuration("http_client_transport_settings.idle_connection_timeout")
	tlsHandshakeTimeout = conf.GetDuration("http_client_transport_settings.tls_handshake_timeout")
	expectContinueTimeout = conf.GetDuration("http_client_transport_settings.expect_continue_timeout")
	dialTimeout = conf.GetDuration("http_client_transport_settings.timeout")
	keepAlive = conf.GetDuration("http_client_transport_settings.keep_alive")

	dialer = &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: keepAlive,
	}

	transport = &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecureSSL},
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ExpectContinueTimeout: expectContinueTimeout,
		DialContext:           (dialer).DialContext,
	}

	noRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	client = &http.Client{
		Timeout:       timeout,
		CheckRedirect: noRedirect,
		Transport:     transport,
	}

	return client
}
