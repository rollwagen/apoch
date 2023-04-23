package main

import (
	"context"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/hokaccha/go-prettyjson"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/samber/lo"
	"go.uber.org/zap/zapcore"

	sq "github.com/Masterminds/squirrel"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
)

var (
	log             *zap.SugaredLogger
	red, bold, cyan func(a ...interface{}) string
)

// discardWriter is a Writer on which all Write calls succeed without doing anything.
type discardWriter struct{}

func (w discardWriter) Write(_ []byte, _ levels.Level) {
}

// Resource represents an AWS resource
type Resource struct {
	ID               string
	PublicIP         string
	Type             string
	AvailabilityZone string
	Region           string
	Account          string
}

func QueryIPsAndScan() {
	log.Debugf("%s Getting started", cyan(""))
	// construct AWS ConfigService query for public IPs; see:
	// https://aws.amazon.com/blogs/architecture/find-public-ips-of-resources-use-aws-config-for-vulnerability-assessment/
	configQueryPublicIPs := sq.Select(
		"resourceId",
		"resourceType",
		"configuration.association.publicIp",
		"accountId",
		"availabilityZone",
		"awsRegion").
		Where(
			sq.And{
				sq.Expr("resourceType='AWS::EC2::NetworkInterface'"),
				sq.Expr("configuration.association.publicIp>'0.0.0.0'"),
			},
		)

	sql, _, err := configQueryPublicIPs.ToSql()
	if err != nil {
		log.Fatal(err)
	}
	log.Debug(sql)

	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatal(err)
	}

	c := configservice.NewFromConfig(cfg)
	output, err := c.SelectResourceConfig(ctx, &configservice.SelectResourceConfigInput{Expression: aws.String(sql)})
	if err != nil {
		log.Fatal(err)
	}

	var resources []Resource
	for _, resultJSON := range output.Results {

		f := prettyjson.NewFormatter()
		f.Indent = 0
		f.Newline = ""
		pretty, _ := f.Format([]byte(resultJSON))
		log.Debug(string(pretty))

		r := Resource{
			ID:               gjson.Get(resultJSON, "resourceId").String(),
			Type:             gjson.Get(resultJSON, "resourceTyp").String(),
			PublicIP:         gjson.Get(resultJSON, "configuration.association.publicIp").String(),
			Account:          gjson.Get(resultJSON, "accountId").String(),
			AvailabilityZone: gjson.Get(resultJSON, "availabilityZone").String(),
			Region:           gjson.Get(resultJSON, "awsRegion").String(),
		}
		log.Infof("Found public IP %s", r.PublicIP)
		resources = append(resources, r)
	}

	log.Infof("Overall found %d public IP addresse(s) via AWS ConfigService", len(resources))

	if len(resources) == 0 {
		log.Info("Skipping scan and exiting. No public IP addresses found.")
		os.Exit(0)
	}

	publicIPs := lo.Map(resources, func(r Resource, index int) string { return r.PublicIP })

	options := runner.Options{
		Host: publicIPs,
		OnResult: func(hr *result.HostResult) {
			resource := lo.Filter(resources, func(r Resource, index int) bool { return r.PublicIP == hr.IP })[0] // should one be one resource with this public IP

			for _, p := range hr.Ports {
				log.Warnw(fmt.Sprintf("%s  %s has open port %s", red("\uF071"), bold(hr.IP), bold(p.Port)), "resource_id", resource.ID, "account", resource.Account)
			}
		},
		Verbose:            false,
		Silent:             true,
		Debug:              false,
		DisableUpdateCheck: true,
		// Ports:              "22,80,443",
		TopPorts:          "100", // [full,100,1000]
		Ping:              false,
		Timeout:           500, // default = 1000
		SkipHostDiscovery: true,
		JSON:              false,
	}

	gologger.DefaultLogger.SetWriter(discardWriter{}) // ignore+suppress naabu log output

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		log.Fatal(err)
	}
	defer naabuRunner.Close()

	log.Info("Starting port scanning for all found public IP addresses for top 100 ports")
	err = naabuRunner.RunEnumeration()
	if err != nil {
		log.Error(err)
	}

	log.Info("Finished all scanning. Exiting.")
}

func main() {
	QueryIPsAndScan()
}

// init initializes the logger
func init() {
	logLevel := zapcore.DebugLevel

	encoderCfg := zapcore.EncoderConfig{
		MessageKey:  "message",
		LevelKey:    "level",
		TimeKey:     "time",
		EncodeLevel: zapcore.CapitalColorLevelEncoder,
	}

	encoder := zapcore.NewConsoleEncoder(encoderCfg)
	core := zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), logLevel)
	log = zap.New(core).Sugar()

	// terminal color output
	red = color.New(color.FgRed).SprintFunc()
	bold = color.New(color.Bold).SprintFunc()
	cyan = color.New(color.FgCyan).SprintFunc()
}
