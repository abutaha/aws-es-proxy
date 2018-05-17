package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	// log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws/signer/v4"
	uuid "github.com/satori/go.uuid"
)

type requestStruct struct {
	Requestid  string
	Datetime   string
	Remoteaddr string
	Requesturi string
	Method     string
	Statuscode int
	Elapsed    float64
	Body       string
}

type responseStruct struct {
	Requestid string
	Body      string
}

type proxy struct {
	scheme       string
	host         string
	region       string
	service      string
	endpoint     string
	verbose      bool
	prettify     bool
	logtofile    bool
	nosignreq    bool
	fileRequest  *os.File
	fileResponse *os.File
	credentials  *credentials.Credentials
}

func newProxy(args ...interface{}) *proxy {
	return &proxy{
		endpoint:  args[0].(string),
		verbose:   args[1].(bool),
		prettify:  args[2].(bool),
		logtofile: args[3].(bool),
		nosignreq: args[4].(bool),
	}
}

func (p *proxy) parseEndpoint() error {
	var link *url.URL
	var err error

	if link, err = url.Parse(p.endpoint); err != nil {
		return fmt.Errorf("error: failure while parsing endpoint: %s. Error: %s",
			p.endpoint, err.Error())
	}

	// Only http/https are supported schemes
	switch link.Scheme {
	case "http", "https":
	default:
		link.Scheme = "https"
	}

	// Unknown schemes sometimes result in empty host value
	if link.Host == "" {
		return fmt.Errorf("error: empty host or protocol information in submitted endpoint (%s)",
			p.endpoint)
	}

	// AWS SignV4 enabled, extract required parts for signing process
	if !p.nosignreq {
		// Extract region and service from link
		parts := strings.Split(link.Host, ".")

		if len(parts) == 5 {
			p.region, p.service = parts[1], parts[2]
		} else {
			return fmt.Errorf("error: submitted endpoint is not a valid Amazon ElasticSearch Endpoint")
		}
	}

	// Update proxy struct
	p.scheme = link.Scheme
	p.host = link.Host

	return nil
}

func (p *proxy) getSigner() *v4.Signer {
	// Refresh credentials after expiration. Required for STS
	if p.credentials == nil {
		sess := session.Must(session.NewSession())
		credentials := sess.Config.Credentials
		p.credentials = credentials
		log.Println("Generated fresh AWS Credentials object")
	}
	return v4.NewSigner(p.credentials)
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestStarted := time.Now()
	dump, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Println("error while dumping request. Error: ", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	ep := *r.URL
	ep.Host = p.host
	ep.Scheme = p.scheme

	req, err := http.NewRequest(r.Method, ep.String(), r.Body)
	if err != nil {
		log.Println("error creating new request. ", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	addHeaders(r.Header, req.Header)

	// Make signV4 optional
	if !p.nosignreq {
		// Start AWS session from ENV, Shared Creds or EC2Role
		signer := p.getSigner()

		// Sign the request with AWSv4
		payload := bytes.NewReader(replaceBody(req))
		signer.Sign(req, payload, p.service, p.region, time.Now())
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !p.nosignreq {
		// AWS credentials expired, need to generate fresh ones
		if resp.StatusCode == 403 {
			p.credentials = nil
			return
		}
	}

	defer resp.Body.Close()

	// Write back headers to requesting client
	copyHeaders(w.Header(), resp.Header)

	// Send response back to requesting client
	body := bytes.Buffer{}
	if _, err := io.Copy(&body, resp.Body); err != nil {
		log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(body.Bytes())

	requestEnded := time.Since(requestStarted)

	/*############################
	## Logging
	############################*/

	rawQuery := string(dump)
	rawQuery = strings.Replace(rawQuery, "\n", " ", -1)
	regex, _ := regexp.Compile("{.*}")
	regEx, _ := regexp.Compile("_msearch|_bulk")
	queryEx := regEx.FindString(rawQuery)

	var query string

	if len(queryEx) == 0 {
		query = regex.FindString(rawQuery)
	} else {
		query = ""
	}

	if p.verbose {
		if p.prettify {
			var prettyBody bytes.Buffer
			json.Indent(&prettyBody, []byte(query), "", "  ")
			t := time.Now()

			fmt.Println()
			fmt.Println("========================")
			fmt.Println(t.Format("2006/01/02 15:04:05"))
			fmt.Println("Remote Address: ", r.RemoteAddr)
			fmt.Println("Request URI: ", ep.RequestURI())
			fmt.Println("Method: ", r.Method)
			fmt.Println("Status: ", resp.StatusCode)
			fmt.Printf("Took: %.3fs\n", requestEnded.Seconds())
			fmt.Println("Body: ")
			fmt.Println(string(prettyBody.Bytes()))
		} else {
			log.Printf(" -> %s; %s; %s; %s; %d; %.3fs\n",
				r.Method, r.RemoteAddr,
				ep.RequestURI(), query,
				resp.StatusCode, requestEnded.Seconds())
		}
	}

	if p.logtofile {

		requestID, _ := uuid.NewV4()

		reqStruct := &requestStruct{
			Requestid:  requestID.String(),
			Datetime:   time.Now().Format("2006/01/02 15:04:05"),
			Remoteaddr: r.RemoteAddr,
			Requesturi: ep.RequestURI(),
			Method:     r.Method,
			Statuscode: resp.StatusCode,
			Elapsed:    requestEnded.Seconds(),
			Body:       query,
		}

		respStruct := &responseStruct{
			Requestid: requestID.String(),
			Body:      string(body.Bytes()),
		}

		y, _ := json.Marshal(reqStruct)
		z, _ := json.Marshal(respStruct)
		p.fileRequest.Write(y)
		p.fileRequest.WriteString("\n")
		p.fileResponse.Write(z)
		p.fileResponse.WriteString("\n")

	}

}

// Recent versions of ES/Kibana require
// "kbn-version" and "content-type: application/json"
// headers to exist in the request.
// If missing requests fails.
func addHeaders(src, dest http.Header) {
	if val, ok := src["Kbn-Version"]; ok {
		dest.Add("Kbn-Version", val[0])
	}

	if val, ok := src["Content-Type"]; ok {
		dest.Add("Content-Type", val[0])
	}
}

// Signer.Sign requires a "seekable" body to sum body's sha256
func replaceBody(req *http.Request) []byte {
	if req.Body == nil {
		return []byte{}
	}
	payload, _ := ioutil.ReadAll(req.Body)
	req.Body = ioutil.NopCloser(bytes.NewReader(payload))
	return payload
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func main() {

	var (
		verbose       bool
		prettify      bool
		logtofile     bool
		nosignreq     bool
		endpoint      string
		listenAddress string
		fileRequest   *os.File
		fileResponse  *os.File
		err           error
	)

	flag.StringVar(&endpoint, "endpoint", "", "Amazon ElasticSearch Endpoint (e.g: https://dummy-host.eu-west-1.es.amazonaws.com)")
	flag.StringVar(&listenAddress, "listen", "127.0.0.1:9200", "Local TCP port to listen on")
	flag.BoolVar(&verbose, "verbose", false, "Print user requests")
	flag.BoolVar(&logtofile, "log-to-file", false, "Log user requests and ElasticSearch responses to files")
	flag.BoolVar(&prettify, "pretty", false, "Prettify verbose and file output")
	flag.BoolVar(&nosignreq, "no-sign-reqs", false, "Disable AWS Signature v4")
	flag.Parse()

	if len(os.Args) < 3 {
		fmt.Println("You need to specify Amazon ElasticSearch endpoint.")
		fmt.Println("Please run with '-h' for a list of available arguments.")
		os.Exit(1)
	}

	p := newProxy(
		endpoint,
		verbose,
		prettify,
		logtofile,
		nosignreq,
	)

	if err = p.parseEndpoint(); err != nil {
		log.Fatalln(err)
	}

	if p.logtofile {
		u1, _ := uuid.NewV4()
		u2, _ := uuid.NewV4()
		requestFname := fmt.Sprintf("request-%s.log", u1.String())
		responseFname := fmt.Sprintf("response-%s.log", u2.String())

		if fileRequest, err = os.Create(requestFname); err != nil {
			log.Fatalln(err.Error())
		}
		if fileResponse, err = os.Create(responseFname); err != nil {
			log.Fatalln(err.Error())
		}

		defer fileRequest.Close()
		defer fileResponse.Close()

		p.fileRequest = fileRequest
		p.fileResponse = fileResponse

	}

	log.Printf("Listening on %s...\n", listenAddress)
	log.Fatal(http.ListenAndServe(listenAddress, p))
}
