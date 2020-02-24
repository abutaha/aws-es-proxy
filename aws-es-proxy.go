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
	"path"
	"regexp"
	"strings"
	"time"

	// log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws/signer/v4"
	humanize "github.com/dustin/go-humanize"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

type prometheusConfiguration struct {
	requestDurationBuckets []float64
	requestSizeBuckets     []float64
	responseSizeBuckets    []float64
}

func csvToBucket(csv string, parser func(string) (float64, error)) ([]float64, error) {
	values := strings.Split(csv, ",")
	bucket := make([]float64, 0, len(values))
	for _, current := range values {
		val, err := parser(strings.TrimSpace(current))
		if err != nil {
			return nil, err
		}
		bucket = append(bucket, val)
	}

	return bucket, nil
}

func newPrometheusConfiguration(requestDurationBucketsCSV string, requestSizeBucketsCSV string, responseSizeBucketCSVs string) (*prometheusConfiguration, error) {

	requestDurationBuckets, err := csvToBucket(requestDurationBucketsCSV, func(csv string) (float64, error) {
		duration, err := time.ParseDuration(csv)
		if err != nil {
			return 0.0, err
		}

		return duration.Seconds(), nil
	})
	if err != nil {
		return nil, err
	}

	sizeParser := func(csv string) (float64, error) {
		size, err := humanize.ParseBytes(csv)
		if err != nil {
			return 0.0, err
		}

		return float64(size), nil
	}

	requestSizeBuckets, err := csvToBucket(requestSizeBucketsCSV, sizeParser)
	if err != nil {
		return nil, err
	}

	responseSizeBuckets, err := csvToBucket(responseSizeBucketCSVs, sizeParser)
	if err != nil {
		return nil, err
	}

	return &prometheusConfiguration{
		requestDurationBuckets: requestDurationBuckets,
		requestSizeBuckets:     requestSizeBuckets,
		responseSizeBuckets:    responseSizeBuckets,
	}, nil
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

type readSeekerNoopCloser struct {
	reader io.ReadSeeker
}

func (r *readSeekerNoopCloser) Read(p []byte) (n int, err error) {
	return r.reader.Read(p)
}

func (r *readSeekerNoopCloser) Seek(offset int64, whence int) (int64, error) {
	return r.reader.Seek(offset, whence)
}

func (r *readSeekerNoopCloser) Close() error {
	return nil
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

func (p *proxy) forwardRequest(req *http.Request) (*http.Response, error) {
	// Make signV4 optional
	if !p.nosignreq {
		// Start AWS session from ENV, Shared Creds or EC2Role
		signer := p.getSigner()

		// Make sure body is a ReadSeeker
		var body io.ReadSeeker
		if seeker, ok := req.Body.(io.ReadSeeker); ok {
			body = seeker
		} else {
			payload, err := ioutil.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			body = &readSeekerNoopCloser{bytes.NewReader(payload)}
		}

		// Sign the request with AWSv4
		signer.Sign(req, body, p.service, p.region, time.Now())
	}

	return http.DefaultClient.Do(req)
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	requestStarted := time.Now()

	var dump []byte
	var err error
	if p.verbose || p.logtofile {
		dump, err = httputil.DumpRequest(r, true)
		if err != nil {
			log.Printf("error while dumping request. Error: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	ep := *r.URL
	ep.Host = p.host
	ep.Scheme = p.scheme
	ep.Path = path.Clean(ep.Path)

	req, err := http.NewRequest(r.Method, ep.String(), r.Body)
	if err != nil {
		log.Printf("error creating new request: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	addHeaders(r.Header, req.Header)

	resp, err := p.forwardRequest(req)
	if err != nil {
		log.Printf("Error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !p.nosignreq {
		// AWS credentials expired, need to generate fresh ones
		// then try again
		if resp.StatusCode == http.StatusForbidden {
			p.credentials = nil

			// Rewind reader to the begining to start over
			if seeker, ok := req.Body.(io.Seeker); ok {
				seeker.Seek(0, io.SeekStart)
			} else {
				log.Printf("Warn: body is not a Seeker: %T", req.Body)
			}

			// Retry the request with new credentials
			resp, err = p.forwardRequest(req)
			if err != nil {
				log.Printf("Error: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
	}

	defer resp.Body.Close()

	// Write back headers to requesting client
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	var clientResponseBody io.Reader
	body := bytes.Buffer{}
	if p.logtofile {
		clientResponseBody = io.TeeReader(resp.Body, &body)
	} else {
		clientResponseBody = resp.Body
	}

	// Send response back to requesting client
	if _, err := io.Copy(w, clientResponseBody); err != nil {
		log.Printf("Error while writing response body: %v", err.Error())
		return
	}

	requestEnded := time.Since(requestStarted)

	/*############################
	## Logging
	############################*/
	if p.verbose || p.logtofile {

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

			requestID := uuid.NewV4()

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

func instrumentHandler(metricPrefix string, prometheusConfig *prometheusConfiguration, handler http.Handler) http.Handler {
	requestTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: metricPrefix + "_requests_total",
			Help: "Total number of requests by HTTP status code.",
		},
		[]string{"code"},
	)
	// Initialize the most likely HTTP status codes.
	requestTotal.WithLabelValues("200")
	requestTotal.WithLabelValues("403")
	requestTotal.WithLabelValues("404")
	requestTotal.WithLabelValues("500")
	requestTotal.WithLabelValues("503")

	requestsInFlight := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: metricPrefix + "_requests_in_flight",
		Help: "Current number of requests being served.",
	})

	// requestSize has no labels, making it a zero-dimensional
	// ObserverVec.
	requestSize := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    metricPrefix + "request_size_bytes",
			Help:    "A histogram of response sizes for requests.",
			Buckets: prometheusConfig.requestSizeBuckets,
		},
		[]string{},
	)

	// responseSize has no labels, making it a zero-dimensional
	// ObserverVec.
	responseSize := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    metricPrefix + "response_size_bytes",
			Help:    "A histogram of response sizes for requests.",
			Buckets: prometheusConfig.responseSizeBuckets,
		},
		[]string{},
	)
	// duration is partitioned by the HTTP method and handler. It uses custom
	// buckets based on the expected request duration.
	duration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    metricPrefix + "request_duration_seconds",
			Help:    "A histogram of latencies for requests.",
			Buckets: prometheusConfig.requestDurationBuckets,
		},
		[]string{"code", "method"},
	)

	timeToWriteHeader := prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: metricPrefix + "time_to_write_header_seconds",
			Help: "A summary of latencies to write header.",
		},
		[]string{"code", "method"},
	)

	prometheus.MustRegister(requestTotal, requestsInFlight, duration, requestSize, responseSize)

	return promhttp.InstrumentHandlerCounter(requestTotal,
		promhttp.InstrumentHandlerInFlight(requestsInFlight,
			promhttp.InstrumentHandlerDuration(duration,
				promhttp.InstrumentHandlerRequestSize(requestSize,
					promhttp.InstrumentHandlerResponseSize(responseSize,
						promhttp.InstrumentHandlerTimeToWriteHeader(timeToWriteHeader, handler),
					),
				),
			),
		),
	)
}

func main() {

	var (
		verbose                 bool
		prettify                bool
		logtofile               bool
		nosignreq               bool
		endpoint                string
		listenAddress           string
		managementListenAddress string
		fileRequest             *os.File
		fileResponse            *os.File
		requestSizeBuckets      string
		requestDurationBuckets  string
		responseSizeBuckets     string
		err                     error
	)

	flag.StringVar(&endpoint, "endpoint", "", "Amazon ElasticSearch Endpoint (e.g: https://dummy-host.eu-west-1.es.amazonaws.com)")
	flag.StringVar(&listenAddress, "listen", "127.0.0.1:9200", "Local TCP port to listen on")
	flag.StringVar(&managementListenAddress, "management-listen", ":8080", "Local TCP port to listen on for management endpoints")
	flag.BoolVar(&verbose, "verbose", false, "Print user requests")
	flag.BoolVar(&logtofile, "log-to-file", false, "Log user requests and ElasticSearch responses to files")
	flag.BoolVar(&prettify, "pretty", false, "Prettify verbose and file output")
	flag.BoolVar(&nosignreq, "no-sign-reqs", false, "Disable AWS Signature v4")
	flag.StringVar(&requestDurationBuckets, "request-duration-buckets", "10ms,50ms,100ms,250ms,500ms,1s,5s", "Prometheus request duration buckets")
	flag.StringVar(&requestSizeBuckets, "request-size-buckets", "128B,256B,512B,1Kb,2Kb,5Kb,25Kb,100Kb,500Kb,1M,2M,5M", "Prometheus request size buckets")
	flag.StringVar(&responseSizeBuckets, "response-size-buckets", "128B,256B,512B,1Kb,2Kb,5Kb,25Kb,100Kb,500Kb,1M,2M,5M", "Prometheus response size buckets")
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

	prometheusConfig, err := newPrometheusConfiguration(requestDurationBuckets, requestSizeBuckets, responseSizeBuckets)
	if err != nil {
		log.Fatalf("Cannot parse prometheus configuration: %v", err)
	}

	if err = p.parseEndpoint(); err != nil {
		log.Fatalln(err)
	}

	if p.logtofile {
		u1 := uuid.NewV4()
		u2 := uuid.NewV4()
		requestFname := fmt.Sprintf("request-%s.log", u1.String())
		responseFname := fmt.Sprintf("response-%s.log", u2.String())

		if fileRequest, err = os.Create(requestFname); err != nil {
			log.Println(err.Error())
		}
		if fileResponse, err = os.Create(responseFname); err != nil {
			log.Println(err.Error())
		}

		defer fileRequest.Close()
		defer fileResponse.Close()

		p.fileRequest = fileRequest
		p.fileResponse = fileResponse

	}

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		mux.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
			fmt.Fprint(w, `{"status": "healthy"}`)
		})
		log.Printf("Listening on %s for management endpoints...\n", managementListenAddress)
		log.Fatal(http.ListenAndServe(managementListenAddress, mux))
	}()

	log.Printf("Listening on %s...\n", listenAddress)
	log.Fatal(http.ListenAndServe(listenAddress, instrumentHandler("aws_es_proxy_handler", prometheusConfig, p)))
}
