package awspkg

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/abutaha/aws-es-proxy/config"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"
)

var conf = config.CFG

// AWSCreds -
type AWSCreds struct {
	Session *session.Session
	Region  string
	Service string
	Profile string
}

func (a *AWSCreds) isExpired() bool {
	return a.Session.Config.Credentials.IsExpired()
}

func (a *AWSCreds) refresh() {
	if a.isExpired() {
		logrus.Debugln("AWS credentials expired, retrieving new ones.")
		// Calling Get() method should get fresh credentials
		a.Session.Config.Credentials.Get()
	}
}

// ForceRefresh -
func (a *AWSCreds) ForceRefresh() {
	a.Session.Config.Credentials.Expire()
	a.Session.Config.Credentials.Get()
}

// SignRequest -
func (a *AWSCreds) SignRequest(request *http.Request, payload io.ReadSeeker) (http.Header, error) {

	// Refresh credentials in case they expired
	a.refresh()

	// Get a new signer
	signer := v4.NewSigner(a.Session.Config.Credentials)

	// Sign the request and return
	return signer.Sign(request, payload, a.Service, a.Region, time.Now())
}

// NewAWSCreds -
func NewAWSCreds() *AWSCreds {

	var (
		credSrc string
		region  string
		profile string
		sess    *session.Session
	)

	if credSrc = conf.GetString("aws.credentials_source"); len(credSrc) == 0 {
		logrus.Warnln("Undefined 'credentials_source' in 'config.yaml'. Using 'auto'.")
		credSrc = "auto"
	}

	if region = conf.GetString("aws.region"); len(region) == 0 {
		logrus.Warnln("Undefined 'region' in 'config.yaml'. Using 'eu-west-1'.")
		region = "eu-west-1"
	}

	if profile = conf.GetString("aws.profile"); len(profile) == 0 {
		logrus.Warnln("Undefined 'profile' in 'config.yaml'. Using 'default'.")
		profile = "default"
	}

	switch credSrc {
	case "auto":
		sess = newAuto(region, profile)
	case "file":
		sess = newFromSharedFile(region, profile)
	default:
		logrus.Warnln("'credentials_source' has an unknown value. Using 'auto'.")
		sess = newAuto(region, profile)
	}

	return &AWSCreds{
		Service: "es",
		Region:  region,
		Profile: profile,
		Session: sess,
	}

}

func newAuto(region string, profile string) *session.Session {

	var (
		opts session.Options
		sess *session.Session
		err  error
	)

	logrus.Debugf("Using '%s' as profile and '%s' as region.", profile, region)
	logrus.Debugln("Searching for AWS Credentials...")

	opts = session.Options{
		Profile: profile,
		Config:  aws.Config{Region: aws.String(region)},
	}

	if sess, err = session.NewSessionWithOptions(opts); err != nil {
		logrus.Errorln(err)
		return nil
	}

	creds, _ := sess.Config.Credentials.Get()
	if creds.ProviderName == "" || creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		logrus.Fatalln("No AWS credentials provider found. Please define a different provider in config.yaml")
		return nil
	}

	logrus.Debugf("AWS credentials provider found: %s", creds.ProviderName)

	useRole := assumeiamRole(sess)
	if useRole != nil {
		fmt.Println("we should use a role")
		cs, err := useRole.Get()
		if err != nil {
			fmt.Println("error:", err)
		}
		fmt.Println(cs)
	}

	return sess

}

func newFromSharedFile(profile string, region string) *session.Session {
	var (
		sharedFilePath   string
		expandSharedFile string
		err              error
		creds            *credentials.Credentials
		awsconf          *aws.Config
		sess             *session.Session
	)

	if sharedFilePath = conf.GetString("aws.credentials_file"); len(sharedFilePath) == 0 {
		logrus.Fatalln("Fatal error: 'credentials_source' in config.yaml is set to 'file',but 'credentials_file' is not defined.Exit 1.")
	}

	if expandSharedFile, err = homedir.Expand(sharedFilePath); err != nil {
		logrus.Fatalf("Fatal error: Failed to expand %s.\nPlease use absolute paths instead.\nError: %s\nExit 1.", sharedFilePath, err.Error())
	}

	creds = credentials.NewSharedCredentials(expandSharedFile, profile)

	awsconf = &aws.Config{
		Region:      aws.String(region),
		Credentials: creds,
	}

	if sess, err = session.NewSession(awsconf); err != nil {
		logrus.Errorln(err)
		return nil
	}

	return sess
}

func assumeiamRole(session *session.Session) *credentials.Credentials {
	var (
		useRole         bool
		useWebIdentity  bool
		iamRole         string
		roleSession     string
		webIdentity     string
		sessionDuration time.Duration
		creds           *credentials.Credentials
	)

	useRole = false
	useWebIdentity = false

	if iamRole = conf.GetString("aws.iam_role_to_assume"); len(iamRole) != 0 {
		logrus.Debugf("'iam_role_to_assume' is defined in config.yaml as %s", iamRole)
		useRole = true
	}

	if useRole {
		if roleSession = conf.GetString("aws.role_session_name"); len(roleSession) != 0 {
			logrus.Debugf("'role_session_name' is defined in config.yaml as %s", roleSession)
		} else {
			logrus.Debugf("No 'role_session_name' defined config.yaml, using 'aws-es-proxy' as session name")
			roleSession = "aws-es-proxy"
		}

		sessionDuration = conf.GetDuration("aws.session_duration")
		logrus.Debugf("'session_duration' is set to %s", sessionDuration.String())
	}

	if webIdentity = conf.GetString("aws.web_identity_token_file"); len(webIdentity) != 0 {
		logrus.Debugf("'web_identity_token_file' is defined in config.yaml as %s", webIdentity)
		logrus.Debugf("WebIdentity will be used to assume iam role.")
		useWebIdentity = true
	}

	if !useRole {
		return nil
	}

	if useWebIdentity {
		logrus.Debugf("Assuming the IAM Role using Web Identity.")
		creds = stscreds.NewWebIdentityCredentials(session, iamRole, roleSession, webIdentity)

	} else {
		logrus.Debugf("Assuming the IAM Role.")
		creds = stscreds.NewCredentials(session, iamRole, func(p *stscreds.AssumeRoleProvider) {
			p.RoleSessionName = roleSession
			p.Duration = sessionDuration
		})
	}

	return creds
}

/*
if c == "environment" {
		id := os.Getenv("AWS_ACCESS_KEY_ID")
		if id == "" {
			id = os.Getenv("AWS_ACCESS_KEY")
		}

		secret := os.Getenv("AWS_SECRET_ACCESS_KEY")
		if secret == "" {
			secret = os.Getenv("AWS_SECRET_KEY")
		}

		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = os.Getenv("AWS_DEFAULT_REGION")
		}

		if id == "" {
			logrus.Fatalln("AWS_ACCESS_KEY_ID or AWS_ACCESS_KEY not found in environment")
		}

		if secret == "" {
			logrus.Fatalln("AWS_SECRET_ACCESS_KEY or AWS_SECRET_KEY not found in environment")
		}

		if region == "" {
			logrus.Fatalln("AWS_REGION or AWS_DEFAULT_REGION not found in environment")
		}

		// creds := credentials.NewEnvCredentials()
		// credValue, _ := creds.Get()
		// fmt.Println(credValue)

	}

*/
