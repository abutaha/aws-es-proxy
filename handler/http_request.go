package handler

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/abutaha/aws-es-proxy/awspkg"
	"github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Proxy -
type Proxy struct {
	HTTPClient *http.Client
	AWSSession *awspkg.AWSCreds
	Host       string
	Scheme     string
}

// ServeHTTP -
func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var (
		start    time.Time
		err      error
		realm    string
		reqDump  []byte
		proxyURL *url.URL
		proxyReq *http.Request
	)

	start = time.Now()

	if conf.GetBool("security.http_auth.enabled") {
		if !checkAuth(req) {
			realm = conf.GetString("security.http_auth.realm")
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", realm))
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("401 Unauthorised.\n"))
			return
		}
	}

	if reqDump, err = httputil.DumpRequest(req, true); err != nil {
		logrus.WithError(err).Errorln("Failed to dump request.")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer req.Body.Close()

	proxyURL = req.URL
	proxyURL.Scheme = p.Scheme
	proxyURL.Host = p.Host
	proxyURL.Path = path.Clean(proxyURL.Path)

	if proxyReq, err = http.NewRequest(req.Method, proxyURL.String(), req.Body); err != nil {
		logrus.WithError(err).Errorln("Failed creating new request.")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	addRequiredHeaders(req.Header, proxyReq.Header)

	if conf.GetBool("aws.enabled") {
		payload := bytes.NewReader(replaceBody(proxyReq))
		_, err = p.AWSSession.SignRequest(proxyReq, payload)
		if err != nil {
			logrus.Errorln(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	resp, err := p.HTTPClient.Do(proxyReq)
	if err != nil {
		logrus.Errorln(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if conf.GetBool("aws.enabled") {
		if resp.StatusCode == 403 {
			logrus.Errorln("Received 403 from AWSAuth, force-refreshing the AWS credentials...")
			p.AWSSession.ForceRefresh()

			// Log exact message
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

	// Write back headers to client
	copyHeaders(w.Header(), resp.Header)

	// Send response back to client
	body := bytes.Buffer{}
	if _, err := io.Copy(&body, resp.Body); err != nil {
		logrus.Errorln(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(resp.StatusCode)
	w.Write(body.Bytes())

	end := time.Since(start)

	// Logging
	if conf.GetBool("logging.enabled") {

		rawQuery := strings.Replace(string(reqDump), "\n", " ", -1)
		regex, _ := regexp.Compile("{.*}")
		regEx, _ := regexp.Compile("_msearch|_bulk")
		queryEx := regEx.FindString(rawQuery)

		query := ""
		if len(queryEx) == 0 {
			query = regex.FindString(rawQuery)
		}

		reqLog := &logRequest{
			Requestid:  primitive.NewObjectID().Hex(),
			Datetime:   time.Now().Format("2006-01-02 15:04:05"),
			Remoteaddr: req.RemoteAddr,
			Requesturi: proxyURL.RequestURI(),
			Method:     req.Method,
			Statuscode: resp.StatusCode,
			Elapsed:    end.Seconds(),
			ReqBody:    query,
			RespBody:   body.String(),
		}

		reqLog.requestLog()
	}
}

func checkAuth(r *http.Request) bool {
	if !conf.GetBool("security.http_auth.enabled") {
		return false
	}

	var (
		provider  string
		reqUser   string
		reqPasswd string
		ok        bool
		username  string
		password  string
		userFile  string
		err       error
		fHandler  *os.File
		line      string
		userpass  []string
	)

	if provider = conf.GetString("security.http_auth.provider"); len(provider) == 0 {
		logrus.Debugln("http_auth provider missing")
		return false
	}

	reqUser, reqPasswd, ok = r.BasicAuth()

	if !ok {
		return false
	}

	switch provider {
	case "config":
		username = conf.GetString("security.http_auth.username")
		password = conf.GetString("security.http_auth.password")

		if reqUser == username && reqPasswd == password {
			return true
		}
	case "file":

		if userFile = conf.GetString("security.http_auth.basic_auth_file"); len(userFile) == 0 {
			logrus.Debugln("http_auth basic auth file is missing")
			return false
		}

		userFile, _ = homedir.Expand(userFile)

		if fHandler, err = os.Open(userFile); err != nil {
			logrus.Debugln("failed to open http auth file, ", err.Error())
			return false
		}
		defer fHandler.Close()

		scanner := bufio.NewScanner(fHandler)
		for scanner.Scan() {
			line = scanner.Text()
			userpass = strings.Split(line, ",")
			if reqUser == userpass[0] && reqPasswd == userpass[1] {
				return true
			}
		}

		// if err := scanner.Err(); err != nil {
		// 	logrus.Fatal(err)
		// }
	}

	return false
}
