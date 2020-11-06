package config

import (
	"os"

	"github.com/sirupsen/logrus"
)

// WriteConfig - Creates config.yaml in current path
func WriteConfig() {
	config := `global:
  # es_endpoint specifies the ElasticSearch URL which will be proxied by this tool.
  # The endpoint can be any active ElasticSearch running on AWS, localhost or any other accessible URL.
  es_endpoint: https://dummy-host.eu-west-1.es.amazonaws.com

  # listen is the address and port in which the proxy will accept connections.
  # A value of (0.0.0.0:9200) mean connections are accepted from anywhere.
  listen: 127.0.0.1:9200

  # strict_https only connects to es_endpoint if it's secured by SSL (es_endpoint is running on HTTPS).
  strict_https: true

  # accept_insecure_ssl rather accept or deny any certificate presented by the server and any host name in that certificate
  accept_insecure_ssl: false

  # request_timeout specifies a time limit for requests made by this Client.
  # The timeout includes connection time, any redirects, and reading the response body.
  # The timer remains running after Get, Head, Post, or Do return and will interrupt reading of the Response.Body.
  # A Timeout of zero (0) means no timeout.
  request_timeout: 120s

aws:
  # enabled directive indicates if aws-es-proxy should pre-sign requests sent to Amazon Elasticsearch
  enabled: true

  # region directive specifies the AWS region in which your Amazon Elasticsearch cluster was created
  region: eu-west-1

  # credentials_source directive indicates how the aws-es-proxy should obtain AWS Credentials
  # Possible values are:
  #   auto: Let aws-sdk-go library find the credentials
  #   file: Use ~/.aws/credentials
  #   environment: Uses AWS_ACCESS_KEY, AWS_SECRET_KEY and AWS_REGION exported environment variables
  #   ec2role: Uses the IAM Role attached to EC2 instance
  credentials_source: auto

  # Linux/Unix: $HOME/.aws/credentials
  # Windows: %USERPROFILE%\.aws\credentials
  # Only works when 'credentials_provider' is set to 'file'
  credentials_file: ~/.aws/credentials

  # profile is used to select AWS credentials from ~/.aws/credentials located under a non-default profile
  # This option only works when (credential_source) is set to (file)
  profile: default

  # iam_role_to_assume directive is used when your IAM user needs to assume a role in another account
  # Value: IAM role arn (Example: arn:aws:iam::<account_number>:role/<role_name>)
  iam_role_to_assume:

  # role_session_name is used when the proxy is assuming an IAM role
  role_session_name:

  # session_duration defines the duration of the session. Default is 15 minutes
  session_duration: 15m

  # web_identity_token_file is used when you are assuming a role with web identity
  # For this option to work, 'iam_role_to_assume' needs to have a valid value
  web_identity_token_file:

security:
  http_auth:
    # Enable HTTP Basic Authentication to protect the proxy from unauthorized access
    # Values: (true) to enable and (false) to disable.
    enabled: false

    realm: Restricted

    # provider selects the method that is used to authenticate the user
    # Possible values are:
    # config - select username/password from this configuration file
    # file - read username/password from a file
    provider: config

    # basic_auth_file path to file having user credentials
    # Only works when 'provider' is set to 'file'
    basic_auth_file: ~/.aws-es-proxy/basic_auth.creds

    # username and password to use.
    # Only works when 'provider' is set to 'config'
    username: admin
    password: admin

  self_certificate:
    # enabled means the proxy will only accept HTTPS connections from users.
    # Values: (true) to enable and (false) to disable.
    enabled: false

    cert_private_key: ~/.aws-es-proxy/key.pem
    cert_public_key: ~/.aws-es-proxy/cert.pem

remote_api:
  enabled: false
  endpoint: 127.0.0.1:9300
  terminate: true
  reload: true

debug:
  enabled: true
  stdout: true
  file_path: ~/.aws-es-proxy/debug.log

logging:
  # enabled specifies if requests and responses sent to Elasticsearch should be logged.
  # This option applies for both requests and responses.
  # Setting to this option to false will disable request/response logging even if
  # log_requests and log_responses are enabled.
  enabled: true

  log_requests:
    # enabled directive logs requests sent to Elasticsearch
    enabled: true

    # log_output specify where to show the request. Available options are:
    # stdout-short: Print the request to console in a single line
    # stdout-long: Print the request to console in a prettier format
    # file: Write the request to log file only
    # both: The request will be shown in console and written to log file
    log_output: both

    # output_file_path directive specifies where to store request logs
    output_file_path: ~/.aws-es-proxy/requests.log

  log_responses:
    # enabled directive logs responses received from Elasticsearch
    enabled: true

    # log_output specify where to show the response. Available options are:
    # stdout: Print the response to console
    # file: Write the response to log file file
    # both: The response will be shown in console and written to log file
    log_output: both

    # output_file_path directive specifies where to store response logs
    output_file_path: ~/.aws-es-proxy/responses.log

http_client_transport_settings:
  # idle_connection_timeout is the maximum amount of time an idle
  # (keep-alive) connection will remain idle before closing itself.
  # Zero means no limit.
  idle_connection_timeout: 60s

  # tls_handshake_timeout specifies the maximum amount of time waiting to wait for a TLS handshake.
  # Zero means no timeout.
  tls_handshake_timeout: 10s

  # expect_continue_timeout, if non-zero, specifies the amount of time to wait for a
  # server's first response headers after fully writing the request headers
  # if the request has an "Expect: 100-continue" header.
  # Zero means no timeout and causes the body to be sent immediately, without waiting for the server to approve.
  # This time does not include the time to send the request header.
  expect_continue_timeout: 1s

  # timeout is the maximum amount of time a dial will wait for a connect to complete.
  # With or without a timeout, the operating system may impose its own earlier timeout.
  # For instance, TCP timeouts are often around 3 minutes.
  timeout: 30s

  # keep_alive specifies the interval between keep-alive probes for an active network connection.
  # If zero, keep-alive probes are sent with a default value (currently 15 seconds),
  # if supported by the protocol and operating system. Network protocols or operating systems that do
  # not support keep-alives ignore this field.
  # If negative, keep-alive probes are disabled.
  keep_alive: 30s

`

	var (
		confFile *os.File
		err      error
	)

	confFile, err = os.Create("config-template.yaml")
	if err != nil {
		logrus.Fatalln("Failed to write config.yaml. Error: ", err.Error())
	}

	confFile.WriteString(config)

}
