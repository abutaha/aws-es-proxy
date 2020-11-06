package handler

import (
	"fmt"
	"net/url"

	"github.com/sirupsen/logrus"
)

// ParseEndpoint -
func ParseEndpoint() (string, string, error) {
	var (
		endpoint string
		link     *url.URL
		err      error
	)

	if endpoint = conf.GetString("global.es_endpoint"); len(endpoint) == 0 {
		logrus.Fatalln("Could not obtain endpoint URL from config.yaml.")
	}

	if link, err = url.Parse(endpoint); err != nil {
		return "", "", fmt.Errorf("error: failure while parsing endpoint: %s. Error: %s", endpoint, err.Error())
	}

	// Only http/https are supported schemes.
	switch link.Scheme {
	case "http", "https":
	default:
		link.Scheme = "http"
	}

	if conf.GetBool("global.strict_https") {
		logrus.Debugln("Using strict https because 'strict_https' is set to true in config.yaml")
		link.Scheme = "https"
	}

	// Unknown schemes sometimes result in empty host value
	if link.Host == "" {
		return "", "", fmt.Errorf("error: empty host or protocol information in submitted endpoint (%s)", endpoint)
	}

	return link.Scheme, link.Host, nil
}
