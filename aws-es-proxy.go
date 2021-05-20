package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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
	"runtime"
	"strings"
	"time"

	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)


var ESURL_REGEXP = regexp.MustCompile(`http(?:s?)://.+\..+\.es.amazonaws.com`)

func logger(debug bool) {

	formatFilePath := func(path string) string {
		arr := strings.Split(path, "/")
		return arr[len(arr)-1]
	}

	if debug {
		logrus.SetLevel(logrus.DebugLevel)
		// logrus.SetReportCaller(true)
	}

	formatter := &logrus.TextFormatter{
		TimestampFormat:        "2006-02-01 15:04:05",
		FullTimestamp:          true,
		DisableLevelTruncation: false,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			return "", fmt.Sprintf("%s:%d", formatFilePath(f.File), f.Line)
		},
	}
	logrus.SetFormatter(formatter)
}

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
	scheme          string
	host            string
	region          string
	service         string
	endpoint        string
	verbose         bool
	prettify        bool
	logtofile       bool
	nosignreq       bool
	fileRequest     *os.File
	fileResponse    *os.File
	credentials     aws.Credentials
	httpClient      *http.Client
	auth            bool
	username        string
	password        string
	realm           string
	remoteTerminate bool
	assumeRole      string
	sso             bool
}

func newProxy(args ...interface{}) *proxy {

	noRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	client := http.Client{
		Timeout:       time.Duration(args[5].(int)) * time.Second,
		CheckRedirect: noRedirect,
	}

	return &proxy{
		endpoint:        args[0].(string),
		verbose:         args[1].(bool),
		prettify:        args[2].(bool),
		logtofile:       args[3].(bool),
		nosignreq:       args[4].(bool),
		httpClient:      &client,
		auth:            args[6].(bool),
		username:        args[7].(string),
		password:        args[8].(string),
		realm:           args[9].(string),
		remoteTerminate: args[10].(bool),
		assumeRole:      args[11].(string),
		sso:             args[12].(bool),
	}
}

func (p *proxy) parseEndpoint() error {
	var (
		link          *url.URL
		err           error
		isAWSEndpoint bool
	)

	if link, err = url.Parse(p.endpoint); err != nil {
		return fmt.Errorf("error: failure while parsing endpoint: %s. Error: %s",
			p.endpoint, err.Error())
	}

	// Only http/https are supported schemes.
	// AWS Elasticsearch uses https by default, but now aws-es-proxy
	// allows non-aws ES clusters as endpoints, therefore we have to fallback
	// to http instead of https

	switch link.Scheme {
	case "http", "https":
	default:
		link.Scheme = "http"
	}

	// Unknown schemes sometimes result in empty host value
	if link.Host == "" {
		return fmt.Errorf("error: empty host or protocol information in submitted endpoint (%s)",
			p.endpoint)
	}

	// Update proxy struct
	p.scheme = link.Scheme
	p.host = link.Host

	// AWS SignV4 enabled, extract required parts for signing process
	if !p.nosignreq {

		split := strings.SplitAfterN(link.Hostname(), ".", 2)

		if len(split) < 2 {
			logrus.Debugln("Endpoint split is less than 2")
		}

		isAWSEndpoint = ESURL_REGEXP.MatchString(p.endpoint)
		if isAWSEndpoint {
			parts := strings.Split(link.Host, ".")
			p.region, p.service = parts[1], "es"
			logrus.Debugln("AWS Region", p.region)
		}

	}

	return nil
}

func (p *proxy) getSigner() *v4.Signer {
	// Refresh credentials after expiration. Required for STS
	
	if p.credentials == (aws.Credentials{}) {
		var cfg aws.Config
		var err error
		
		if p.sso {
			profile := os.Getenv("AWS_PROFILE")
			logrus.Debugf("Using profile: %s", profile)
			cfg, err = config.LoadDefaultConfig(
				context.TODO(),
				config.WithSharedConfigProfile(profile),
			)
		} else {
			cfg, err = config.LoadDefaultConfig(context.TODO(),
					config.WithRegion(p.region),
			)
		}
		if err != nil {
			logrus.Infoln(err)
		}

		awsRoleARN := os.Getenv("AWS_ROLE_ARN")
		awsWebIdentityTokenFile := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")

		if awsRoleARN != "" && awsWebIdentityTokenFile != "" {
			logrus.Infof("Using web identity credentials with role %s", awsRoleARN)
			credsProvider := stscreds.NewWebIdentityRoleProvider(sts.NewFromConfig(cfg), awsRoleARN, stscreds.IdentityTokenFile(awsWebIdentityTokenFile), func(o *stscreds.WebIdentityRoleOptions) {
				o.RoleSessionName = ""
			})
			cfg.Credentials = aws.NewCredentialsCache(credsProvider)
		} else if p.assumeRole != "" {
			client := sts.NewFromConfig(cfg)
			identity, err := client.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
			if err != nil {
				logrus.Infoln("error:", err)
				os.Exit(1)
			}
		
			logrus.Infof(
				"Account: %s\nUserID: %s\nARN: %s\n",
				aws.ToString(identity.Account),
				aws.ToString(identity.UserId),
				aws.ToString(identity.Arn),
			)
			logrus.Infof("Assuming credentials from %s", p.assumeRole)
			credsProvider := stscreds.NewAssumeRoleProvider(client, p.assumeRole, func(assumeRoleOptions *stscreds.AssumeRoleOptions) {
				assumeRoleOptions.Duration = 17 * time.Minute
			})
			cfg.Credentials = aws.NewCredentialsCache(credsProvider, func(options *aws.CredentialsCacheOptions) {
				options.ExpiryWindow = 13 * time.Minute
				options.ExpiryWindowJitterFrac = 0.1
			})
		}
		creds, err := cfg.Credentials.Retrieve(context.Background())
		if err != nil {
			logrus.Fatalf("Unable to retrieve credentials %s", err)
		}
		p.credentials = creds
		logrus.Infoln("Generated fresh AWS Credentials object")
	}

	return v4.NewSigner()
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.remoteTerminate && r.URL.Path == "/terminate-proxy" && r.Method == http.MethodPost {
		logrus.Infoln("Terminate Signal")
		os.Exit(0)
	}

	if p.auth {
		user, pass, ok := r.BasicAuth()

		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(p.username)) != 1 || subtle.ConstantTimeCompare([]byte(pass), []byte(p.password)) != 1 {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", p.realm))
			w.WriteHeader(401)
			_, _ = w.Write([]byte("Unauthorised.\n"))
			return
		}
	}

	requestStarted := time.Now()

	var (
		err  error
		dump []byte
		req  *http.Request
	)

	if dump, err = httputil.DumpRequest(r, true); err != nil {
		logrus.WithError(err).Errorln("Failed to dump request.")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer r.Body.Close()

	proxied := *r.URL
	proxied.Host = p.host
	proxied.Scheme = p.scheme
	proxied.Path = path.Clean(proxied.Path)

	if req, err = http.NewRequest(r.Method, proxied.String(), r.Body); err != nil {
		logrus.WithError(err).Errorln("Failed creating new request.")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	addHeaders(r.Header, req.Header)

	// Make signV4 optional
	if !p.nosignreq {
		// Start AWS session from ENV, Shared Creds or EC2Role
		signer := p.getSigner()


		// Sign the request with AWSv4
		payload := replaceBody(req)
		payloadHash := sha256.Sum256(payload)
		err := signer.SignHTTP(context.TODO(), p.credentials, req, hex.EncodeToString(payloadHash[:]), p.service, p.region, time.Now())
		if err != nil {
			p.credentials = aws.Credentials{}
			logrus.Errorln("Failed to sign", err)
			http.Error(w, "Failed to sign", http.StatusForbidden)
			return
		}
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		logrus.Errorln(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !p.nosignreq {
		// AWS credentials expired, need to generate fresh ones
		if resp.StatusCode == 403 {
			logrus.Errorln("Received 403 from AWSAuth, invalidating credentials for retrial")
			p.credentials = aws.Credentials{}

			logrus.Debugln("Received Status code from AWS:", resp.StatusCode)
			b := bytes.Buffer{}
			if _, err := io.Copy(&b, resp.Body); err != nil {
				logrus.WithError(err).Errorln("Failed to decode body")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			logrus.Debugln("Received headers from AWS:", resp.Header)
			logrus.Debugln("Received body from AWS:", string(b.Bytes()))
		}
	}

	defer resp.Body.Close()

	// Write back headers to requesting client
	copyHeaders(w.Header(), resp.Header)

	// Send response back to requesting client
	body := bytes.Buffer{}
	if _, err := io.Copy(&body, resp.Body); err != nil {
		logrus.Errorln(err)
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
			fmt.Println("Request URI: ", proxied.RequestURI())
			fmt.Println("Method: ", r.Method)
			fmt.Println("Status: ", resp.StatusCode)
			fmt.Printf("Took: %.3fs\n", requestEnded.Seconds())
			fmt.Println("Body: ")
			fmt.Println(string(prettyBody.Bytes()))
		} else {
			log.Printf(" -> %s; %s; %s; %s; %d; %.3fs\n",
				r.Method, r.RemoteAddr,
				proxied.RequestURI(), query,
				resp.StatusCode, requestEnded.Seconds())
		}
	}

	if p.logtofile {

		requestID := primitive.NewObjectID().Hex()

		reqStruct := &requestStruct{
			Requestid:  requestID,
			Datetime:   time.Now().Format("2006/01/02 15:04:05"),
			Remoteaddr: r.RemoteAddr,
			Requesturi: proxied.RequestURI(),
			Method:     r.Method,
			Statuscode: resp.StatusCode,
			Elapsed:    requestEnded.Seconds(),
			Body:       query,
		}

		respStruct := &responseStruct{
			Requestid: requestID,
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
// "content-type: application/json" and
// either "kbn-version" or "kbn-xsrf"
// headers to exist in the request.
// If missing requests fails.
func addHeaders(src, dest http.Header) {
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
		if k != "Authorization" {
			for _, v := range vals {
				dst.Add(k, v)
			}
		}

	}
}

func main() {

	var (
		debug           bool
		auth            bool
		username        string
		password        string
		realm           string
		verbose         bool
		prettify        bool
		logtofile       bool
		nosignreq       bool
		ver             bool
		endpoint        string
		listenAddress   string
		fileRequest     *os.File
		fileResponse    *os.File
		err             error
		timeout         int
		remoteTerminate bool
		assumeRole      string
		sso             bool
	)

	flag.StringVar(&endpoint, "endpoint", "", "Amazon ElasticSearch Endpoint (e.g: https://dummy-host.eu-west-1.es.amazonaws.com)")
	flag.StringVar(&listenAddress, "listen", "127.0.0.1:9200", "Local TCP port to listen on")
	flag.BoolVar(&verbose, "verbose", false, "Print user requests")
	flag.BoolVar(&logtofile, "log-to-file", false, "Log user requests and ElasticSearch responses to files")
	flag.BoolVar(&prettify, "pretty", false, "Prettify verbose and file output")
	flag.BoolVar(&nosignreq, "no-sign-reqs", false, "Disable AWS Signature v4")
	flag.BoolVar(&debug, "debug", false, "Print debug messages")
	flag.BoolVar(&ver, "version", false, "Print aws-es-proxy version")
	flag.IntVar(&timeout, "timeout", 15, "Set a request timeout to ES. Specify in seconds, defaults to 15")
	flag.BoolVar(&auth, "auth", false, "Require HTTP Basic Auth")
	flag.StringVar(&username, "username", "", "HTTP Basic Auth Username")
	flag.StringVar(&password, "password", "", "HTTP Basic Auth Password")
	flag.StringVar(&realm, "realm", "", "Authentication Required")
	flag.BoolVar(&remoteTerminate, "remote-terminate", false, "Allow HTTP remote termination")
	flag.StringVar(&assumeRole, "assume", "", "Optionally specify role to assume")
	flag.BoolVar(&sso, "sso", false, "Use AWS SSO for auth")
	flag.Parse()

	if endpoint == "" {
		if v, ok := os.LookupEnv(strings.ToUpper("endpoint")); ok {
			endpoint = v
		} else {
			text := "You need to specify Amazon ElasticSearch endpoint.\n" +
				"You can use either argument '-endpoint' OR environment variable 'ENDPOINT'.\n" +
				"Please run with '-h' for a list of available arguments."
			fmt.Println(text)
			os.Exit(1)
		}
	}

	if debug {
		logger(true)
	} else {
		logger(false)
	}

	if ver {
		version := 1.1
		logrus.Infof("Current version is: v%.1f", version)
		os.Exit(0)
	}

	if auth {
		if len(username) == 0 || len(password) == 0 {
			fmt.Println("You need to specify username and password when using authentication.")
			fmt.Println("Please run with '-h' for a list of available arguments.")
			os.Exit(1)
		}
	}

	p := newProxy(
		endpoint,
		verbose,
		prettify,
		logtofile,
		nosignreq,
		timeout,
		auth,
		username,
		password,
		realm,
		remoteTerminate,
		assumeRole,
		sso,
	)

	if err = p.parseEndpoint(); err != nil {
		logrus.Fatalln(err)
		os.Exit(1)
	}

	if p.logtofile {

		requestFname := fmt.Sprintf("request-%s.log", primitive.NewObjectID().Hex())
		if fileRequest, err = os.Create(requestFname); err != nil {
			log.Fatalln(err.Error())
		}
		defer fileRequest.Close()

		responseFname := fmt.Sprintf("response-%s.log", primitive.NewObjectID().Hex())
		if fileResponse, err = os.Create(responseFname); err != nil {
			log.Fatalln(err.Error())
		}
		defer fileResponse.Close()

		p.fileRequest = fileRequest
		p.fileResponse = fileResponse

	}

	logrus.Infof("Listening on %s...\n", listenAddress)
	logrus.Fatalln(http.ListenAndServe(listenAddress, p))
}
