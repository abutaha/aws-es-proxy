package handler

import (
	"bytes"
	"io/ioutil"
	"net/http"
)

// AWS Signer.Sign requires a "seekable" body to sum body's sha256
func replaceBody(req *http.Request) []byte {
	if req.Body == nil {
		return []byte{}
	}
	payload, _ := ioutil.ReadAll(req.Body)
	req.Body = ioutil.NopCloser(bytes.NewReader(payload))
	return payload
}

// Injects additional headers required by Elasticsearch and Kibana
// Usually the end user forget to submit them with his request, causing ES/Kibana to reject the request
func addRequiredHeaders(src, dest http.Header) {
	if val, ok := src["Kbn-Version"]; ok {
		dest.Add("Kbn-Version", val[0])
	}

	if val, ok := src["Content-Type"]; ok {
		dest.Add("Content-Type", val[0])
	}

	if val, ok := src["Kbn-Xsrf"]; ok {
		dest.Add("Kbn-Xsrf", val[0])
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		if k != "Authorization" {
			for _, v := range vals {
				dst.Add(k, v)
			}
		}
	}
}
