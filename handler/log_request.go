package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"
)

type logRequest struct {
	Requestid  string  `json:"request_id"`
	Datetime   string  `json:"date_time"`
	Remoteaddr string  `json:"remote_addr"`
	Requesturi string  `json:"request_uri"`
	Method     string  `json:"method"`
	Statuscode int     `json:"status_code"`
	Elapsed    float64 `json:"elapsed"`
	ReqBody    string  `json:"request_body"`
	RespBody   string  `json:"response_body"`
}

var (
	requestLogFile  *os.File
	responseLogFile *os.File
)

func init() {
	if !conf.GetBool("logging.enabled") {
		logrus.Warnln("HTTP requests and responses logging is disabled in config.yaml (logging.enabled=false). Client Requests will not be logged.")
		return
	}

	// Open log file for requests
	if conf.GetBool("logging.log_requests.enabled") {
		switch conf.GetString("logging.log_requests.log_output") {
		case "file", "both":
			reqFpath := conf.GetString("logging.log_requests.output_file_path")
			if len(reqFpath) == 0 {
				logrus.Fatalln("No file mentioned")
			}
			reqFpath, _ = homedir.Expand(reqFpath)
			requestLogFile, _ = os.OpenFile(reqFpath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		}
	}

	// Open log file for responses
	if conf.GetBool("logging.log_responses.enabled") {
		switch conf.GetString("logging.log_responses.log_output") {
		case "file", "both":
			respFpath := conf.GetString("logging.log_responses.output_file_path")
			if len(respFpath) == 0 {
				logrus.Fatalln("No file mentioned")
			}
			respFpath, _ = homedir.Expand(respFpath)
			responseLogFile, _ = os.OpenFile(respFpath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		}
	}
}

func (r *logRequest) requestLog() {
	if !conf.GetBool("logging.enabled") {
		return
	}

	if conf.GetBool("logging.log_requests.enabled") {

		toStdoutShort := func() {
			fmt.Printf("%s -> %d; %s; %.3fs; %s; %s; %s; \n",
				time.Now().Format("2006-01-02 15:04:05"), r.Statuscode, r.Method, r.Elapsed, r.Remoteaddr,
				r.Requesturi, r.ReqBody)
		}

		toStdoutLong := func() {
			var prettyReq bytes.Buffer
			json.Indent(&prettyReq, []byte(r.ReqBody), "", "  ")

			fmt.Println()
			fmt.Println("========================")
			fmt.Println("Request ID: ", r.Requestid)
			fmt.Println("Date/Time: ", time.Now().Format("2006-01-02 15:04:05"))
			fmt.Println("Method: ", r.Method)
			fmt.Println("Remote Address: ", r.Remoteaddr)
			fmt.Println("Request URI: ", r.Requesturi)
			fmt.Println("Status: ", r.Statuscode)
			fmt.Printf("Took: %.3fs\n", r.Elapsed)
			fmt.Println("Body: ")
			fmt.Println(prettyReq.String())
		}

		toFile := func() {
			data := struct {
				Requestid  string
				Datetime   string
				Remoteaddr string
				Requesturi string
				Method     string
				Statuscode int
				Elapsed    float64
				ReqBody    string
			}{r.Requestid, r.Datetime, r.Remoteaddr, r.Requesturi, r.Method, r.Statuscode, r.Elapsed, r.ReqBody}

			z, _ := json.Marshal(data)
			requestLogFile.Write(z)
			requestLogFile.WriteString("\n")
		}

		switch conf.GetString("logging.log_requests.log_output") {
		case "stdout-short":
			toStdoutShort()
		case "stdout-long":
			toStdoutLong()
		case "file":
			toFile()
		case "both":
			toStdoutLong()
			toFile()
		}
	}

	if conf.GetBool("logging.log_responses.enabled") {

		toStdout := func() {
			var prettyResp bytes.Buffer
			json.Indent(&prettyResp, []byte(r.RespBody), "", "  ")
			fmt.Println()
			fmt.Println("++++++++++++++++++++++++")
			fmt.Println("Response ID: ", r.Requestid)
			fmt.Println("Body: ")
			fmt.Println(prettyResp.String())
		}

		toFile := func() {
			data := struct {
				Request string
				Body    string
			}{r.Requestid, r.RespBody}

			z, _ := json.Marshal(data)
			responseLogFile.Write(z)
			responseLogFile.WriteString("\n")
		}

		switch conf.GetString("logging.log_responses.log_output") {
		case "stdout":
			toStdout()
		case "file":
			toFile()
		case "both":
			toStdout()
			toFile()
		}
	}
}
