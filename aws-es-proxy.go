package main
import (
        "bytes"
        "flag"
        "fmt"
        "io"
        "io/ioutil"
        "log"
        "net/http"
        "net/http/httputil"
        "net/url"
        "os"
        "strings"
        "time"
        "regexp"


        "github.com/aws/aws-sdk-go/aws/session"
        "github.com/aws/aws-sdk-go/aws/signer/v4"
)

type proxy struct {
        Scheme  string
        Host    string
        Region  string
        Service string
        Verbose bool
        Signer  *v4.Signer
}

func copyHeaders(dst, src http.Header) {
        for k, vals := range src {
                for _, v := range vals {
                        dst.Add(k, v)
                }
        }
}

func replaceBody(req *http.Request) []byte {
        if req.Body == nil {
                return []byte{}
        }
        payload, _ := ioutil.ReadAll(req.Body)
        req.Body = ioutil.NopCloser(bytes.NewReader(payload))
        return payload
}

func parseEndpoint(endpoint string, p *proxy) {
        link, err := url.Parse(endpoint)
        if err != nil {
                log.Fatalf("ERROR: Failed parsing endpoint: %s\n", endpoint)
        }

        // Only http/https are supported schemes
        scheme := func(x string) string {
                switch x {
                case "http", "https":
                        return x
                }
                return "https"
        }
        link.Scheme = scheme(link.Scheme)

        // Unkown schemes sometimes result in empty host value
        if link.Host == "" {
                log.Fatalf("ERROR: Empty host information in submitted endpoint (%s)\n", endpoint)
        }

        // Extract region and service from link
        parts := strings.Split(link.Host, ".")
        var region, service string

        if len(parts) == 5 {
                region, service = parts[1], parts[2]
        } else {
                log.Fatalln("ERROR: Submitted endpoint is not a valid Amazon ElasticSearch Endpoint")
        }

        // Build proxy struct
        p.Scheme = link.Scheme
        p.Host = link.Host
        p.Region = region
        p.Service = service

}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
        requestStarted := time.Now()
        dump, err := httputil.DumpRequest(r, true)
        defer r.Body.Close()

        respondError := func(err error) {
                w.WriteHeader(http.StatusBadRequest)
                w.Write([]byte(err.Error()))
        }

        endpoint := *r.URL
        endpoint.Host = p.Host
        endpoint.Scheme = p.Scheme

        req, err := http.NewRequest(r.Method, endpoint.String(), r.Body)
        if err != nil {
                respondError(err)
                return
        }

        // Workaround for ES 5.1 and Kibana 5.1.1
        if val, ok := r.Header["Kbn-Version"]; ok {
                req.Header.Set("Kbn-Version", val[0])
        }

        // Sign the request with AWSv4
        payload := bytes.NewReader(replaceBody(req))
        p.Signer.Sign(req, payload, p.Service, p.Region, time.Now())

        resp, err := http.DefaultClient.Do(req)
        if err != nil {
                log.Println(err)
                respondError(err)
                return
        }

        defer resp.Body.Close()

        // Write back received headers
        copyHeaders(w.Header(), resp.Header)

        buf := bytes.Buffer{}
        if _, err := io.Copy(&buf, resp.Body); err != nil {
                log.Fatal(err)
        }

        // Send response back
        w.WriteHeader(resp.StatusCode)
        w.Write(buf.Bytes())

        // Log everything
        remote_addr := r.RemoteAddr
        raw_query :=string(dump)
        raw_query = strings.Replace(raw_query,"\n"," ",-1)
        regex, _ := regexp.Compile("{.*}")
        reg_ex, _ := regexp.Compile("_msearch|_bulk")
        query_ex := reg_ex.FindString(raw_query)
        var query string
        if len(query_ex) == 0  {
                query = regex.FindString(raw_query)
        } else {
                query = ""
        }
        if p.Verbose {
                requestEnded := time.Since(requestStarted)
                log.Printf(" -> %s; %s; %s; %s; %d; %.3fs\n",
                        r.Method, remote_addr, endpoint.RequestURI(), query, resp.StatusCode, requestEnded.Seconds())
        }

}

func main() {
        var endpoint, listenAddress string
        var verbose bool

        // TODO: Use a more sophisticated args parser that can enforce arguments
        flag.StringVar(&endpoint, "endpoint", "", "Amazon ElasticSearch Endpoint (e.g: https://dummy-host.eu-west-1.es.amazonaws.com)")
        flag.StringVar(&listenAddress, "listen", "127.0.0.1:9200", "Local TCP port to listen on")
        flag.BoolVar(&verbose, "verbose", false, "Print user requests")
        flag.Parse()

        if len(os.Args) < 3 {
                fmt.Println("You need to specify Amazon ElasticSearch endpoint.")
                fmt.Println("Please run with '-h' for a list of available arguments.")
                os.Exit(1)
        }

        // Start AWS session from ENV, Shared Creds or EC2Role
        sess, err := session.NewSession()
        if err != nil {
                log.Fatalln(err)
        }
        signer := v4.NewSigner(sess.Config.Credentials)

        mux := &proxy{Verbose: verbose, Signer: signer}
        parseEndpoint(endpoint, mux)

        fmt.Printf("Listening on %s\n", listenAddress)
        log.Fatal(http.ListenAndServe(listenAddress, mux))
}
