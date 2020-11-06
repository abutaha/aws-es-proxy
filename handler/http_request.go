package handler

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/abutaha/aws-es-proxy/awspkg"
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
		reqDump  []byte
		proxyURL *url.URL
		proxyReq *http.Request
	)

	start = time.Now()

	// if conf.GetBool("security.http_auth.enabled") {
	// 	checkAuth(req)
	// }

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
	return true
}

/*
if p.auth {
		user, pass, ok := r.BasicAuth()

		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(p.username)) != 1 || subtle.ConstantTimeCompare([]byte(pass), []byte(p.password)) != 1 {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", p.realm))
			w.WriteHeader(401)
			_, _ = w.Write([]byte("Unauthorised.\n"))
			return
		}
	}
*/
