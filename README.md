# aws-es-proxy

[![Docker Pulls](https://img.shields.io/docker/pulls/abutaha/aws-es-proxy.svg)](https://hub.docker.com/r/abutaha/aws-es-proxy/)

**aws-es-proxy** is a small web server application sitting between your HTTP client (browser, curl, etc...) and Amazon Elasticsearch service. It will sign your requests using latest [AWS Signature Version 4](http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html) before sending the request to Amazon Elasticsearch. When response is back from Amazon Elasticsearch, this response will be sent back to your HTTP client.

Kibana requests are also signed automatically.

## Installation

### Download binary executable

**aws-es-proxy** has single executable binaries for Linux, Mac and Windows.

Download the latest [aws-es-proxy release](https://github.com/abutaha/aws-es-proxy/releases/).

### Docker

There is an official docker image available for aws-es-proxy. To run the image:

```sh
# v0.9 and newer (latest always point to the latest release):

docker run --rm -v ~/.aws:/root/.aws -p 9200:9200 abutaha/aws-es-proxy:v1.0 -endpoint https://dummy-host.ap-southeast-2.es.amazonaws.com -listen 0.0.0.0:9200

v.08:

docker run --rm -it abutaha/aws-es-proxy ./aws-es-proxy -endpoint https://dummy-host.ap-southeast-2.es.amazonaws.com

```

To expose a port number other than the default 9200, pass an environment variable of `PORT_NUM` to docker with the port number you wish to expose for your service.

### Via homebrew

```sh
brew install aws-es-proxy
```

### Build from Source

#### Dependencies:
* go1.14+

```sh
#requires go1.14
go build github.com/abutaha/aws-es-proxy
```

## Configuring Credentials

Before using **aws-es-proxy**, ensure that you've configured your AWS IAM user credentials. The best way to configure credentials on a development machine is to use the `~/.aws/credentials` file, which might look like:

```
[default]
aws_access_key_id = AKID1234567890
aws_secret_access_key = MY-SECRET-KEY
```

Alternatively, you can set the following environment variables:

```
export AWS_ACCESS_KEY_ID=AKID1234567890
export AWS_SECRET_ACCESS_KEY=MY-SECRET-KEY
```

**aws-es-proxy** also supports `IAM roles`. To use IAM roles, you need to modify your Amazon Elasticsearch access policy to allow access from that role. Below is an Amazon Elasticsearch `access policy` example allowing access from any EC2 instance with an IAM role called `ec2-aws-elasticsearch`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::012345678910:role/ec2-aws-elasticsearch"
      },
      "Action": "es:*",
      "Resource": "arn:aws:es:eu-west-1:012345678910:domain/test-es-domain/*"
    }
  ]
}
```



## Usage example:

You can use either argument `-endpoint` OR environment variable `ENDPOINT` to specify AWS ElasticSearch endpoint.

```sh
./aws-es-proxy -endpoint https://test-es-somerandomvalue.eu-west-1.es.amazonaws.com
Listening on 127.0.0.1:9200
```

```sh
export ENDPOINT=https://test-es-somerandomvalue.eu-west-1.es.amazonaws.com

./aws-es-proxy  -listen 10.0.0.1:9200 -verbose
Listening on 10.0.0.1:9200
```

*aws-es-proxy* listens on 127.0.0.1:9200 if no additional argument is provided. You can change the IP and Port passing the argument `-listen`

```sh
./aws-es-proxy -listen :8080 -endpoint ...
./aws-es-proxy -listen 10.0.0.1:9200 -endpoint ...
```

By default, *aws-es-proxy* will not display any message in the console. However, it has the ability to print requests being sent to Amazon Elasticsearch, and the duration it takes to receive the request back. This can be enabled using the option `-verbose`

```sh
./aws-es-proxy -verbose ...
Listening on 127.0.0.1:9200
2016/10/31 19:48:23  -> GET / 200 1.054s
2016/10/31 19:48:30  -> GET /_cat/indices?v 200 0.199s
2016/10/31 19:48:37  -> GET /_cat/shards?v 200 0.196s
2016/10/31 19:48:49  -> GET /_cat/allocation?v 200 0.179s
2016/10/31 19:49:10  -> PUT /my-test-index 200 0.347s
```

For a full list of available options, use `-h`:

```sh
./aws-es-proxy -h
Usage of ./aws-es-proxy:
  -auth
        Require HTTP Basic Auth
  -debug
        Print debug messages
  -endpoint string
        Amazon ElasticSearch Endpoint (e.g: https://dummy-host.eu-west-1.es.amazonaws.com)
  -listen string
        Local TCP port to listen on (default "127.0.0.1:9200")
  -log-to-file
        Log user requests and ElasticSearch responses to files
  -no-sign-reqs
        Disable AWS Signature v4
  -password string
        HTTP Basic Auth Password
  -pretty
        Prettify verbose and file output
  -realm string
        Authentication Required
  -remote-terminate
        Allow HTTP remote termination
  -timeout int
        Set a request timeout to ES. Specify in seconds, defaults to 15 (default 15)
  -username string
        HTTP Basic Auth Username
  -verbose
        Print user requests
  -version
        Print aws-es-proxy version
```


## Using HTTP Clients

After you run *aws-es-proxy*, you can now open your Web browser on [http://localhost:9200](http://localhost:9200). Everything should be working as you have your own instance of ElasticSearch running on port 9200.

To access Kibana, use [http://localhost:9200/_plugin/kibana/app/kibana](http://localhost:9200/_plugin/kibana/app/kibana)
