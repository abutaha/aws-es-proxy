package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/abutaha/aws-es-proxy/awspkg"
	"github.com/abutaha/aws-es-proxy/config"
	"github.com/abutaha/aws-es-proxy/handler"
	"github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"
)

var conf = config.CFG

func logger(debug bool, stdout bool) {

	logFilePath := conf.GetString("debug.file_path")
	// if len(logFilePath) == 0 {}

	logFilePath, _ = homedir.Expand(logFilePath)
	logFile, _ := os.OpenFile(logFilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)

	formatFilePath := func(path string) string {
		arr := strings.Split(path, "/")
		return arr[len(arr)-1]
	}

	if debug {
		logrus.SetLevel(logrus.DebugLevel)
		// logrus.SetReportCaller(true)
	}

	formatter := &logrus.TextFormatter{
		TimestampFormat:        "2006-01-02 15:04:05",
		FullTimestamp:          true,
		DisableLevelTruncation: false,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			return "", fmt.Sprintf("%s:%d", formatFilePath(f.File), f.Line)
		},
	}
	logrus.SetFormatter(formatter)

	if stdout {
		logrus.SetOutput(io.MultiWriter(os.Stdout, logFile))
	} else {
		logrus.SetOutput(logFile)
	}
}

func main() {

	var (
		debug         bool
		stdout        bool
		listenAddress string
		certPriv      string
		certPub       string
		ver           bool
		genConf       bool
	)

	version := "2.0"

	flag.BoolVar(&ver, "version", false, "Print aws-es-proxy version")
	flag.BoolVar(&genConf, "gen-config", false, "Generates config.yaml")
	flag.Parse()

	if ver {
		logrus.Infof("Current version is: %s", version)
		os.Exit(0)
	}

	if genConf {
		logrus.Infoln("Generating new config file.")
		config.WriteConfig()
		logrus.Infoln("File config-template.yaml created. Please edit and rename it to config.yaml.")
		os.Exit(0)
	}

	// Setup logger
	userHome, _ := homedir.Dir()
	confDir := filepath.Join(userHome, ".aws-es-proxy")
	os.Mkdir(confDir, 0755)

	debug, stdout = false, false

	if conf.GetBool("debug.enabled") {
		debug = true
		if conf.GetBool("debug.stdout") {
			stdout = true
		}
	}
	logger(debug, stdout)

	// Continue only if host and scheme are sucessfully parsed
	scheme, host, err := handler.ParseEndpoint()
	if err != nil {
		logrus.WithError(err).Fatalln("Error parsing es_endpoint from config.yaml")
	}

	proxy := &handler.Proxy{
		HTTPClient: handler.NewHTTPClient(),
		Host:       host,
		Scheme:     scheme,
	}

	if conf.GetBool("aws.enabled") {
		proxy.AWSSession = awspkg.NewAWSCreds()
	}

	if listenAddress = conf.GetString("global.listen"); len(listenAddress) == 0 {
		logrus.Fatalln("Listen address is not defined in config.yaml")
	}

	logrus.Infof("aws-es-proxy %s started. Listening on %s", version, listenAddress)

	if conf.GetBool("security.self_certificate.enabled") {
		certPriv, _ = homedir.Expand(conf.GetString("security.self_certificate.cert_private_key"))
		certPub, _ = homedir.Expand(conf.GetString("security.self_certificate.cert_public_key"))
		logrus.Infoln("Loaded SSL certificates")
		logrus.Fatalln(http.ListenAndServeTLS(listenAddress, certPub, certPriv, nil))
	} else {
		logrus.Fatalln(http.ListenAndServe(listenAddress, proxy))
	}

}
