package apoch

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/aws/aws-sdk-go-v2/service/ec2"

	sq "github.com/Masterminds/squirrel"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/fatih/color"
	"github.com/hokaccha/go-prettyjson"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
	"github.com/samber/lo"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
)

var red, bold, cyan func(a ...interface{}) string

func QueryIPsAndScan(log *zap.SugaredLogger, skipScan bool) error {
	log.Debugf("%s Gopher time", cyan(""))
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
		log.Error(err)
		return err
	}

	log.Info("Getting a list of all public IP addresses tied to VPC via AWS ConfigService query")
	log.Debug(sql)

	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Error(err)
		return err
	}

	c := configservice.NewFromConfig(cfg)
	output, err := c.SelectResourceConfig(ctx, &configservice.SelectResourceConfigInput{Expression: aws.String(sql)})
	if err != nil {
		log.Error(err)
		return err
	}

	var resources []Resource
	for _, resultJSON := range output.Results {

		log.Debug(prettifyJSON(resultJSON))

		r := Resource{
			ID:               gjson.Get(resultJSON, "resourceId").String(),
			Type:             gjson.Get(resultJSON, "resourceTyp").String(),
			PublicIP:         net.ParseIP(gjson.Get(resultJSON, "configuration.association.publicIp").String()),
			Account:          gjson.Get(resultJSON, "accountId").String(),
			AvailabilityZone: gjson.Get(resultJSON, "availabilityZone").String(),
			Region:           gjson.Get(resultJSON, "awsRegion").String(),
		}
		log.Infof("Found public IP %s", r.PublicIP)
		resources = append(resources, r)
	}

	log.Infof("Overall found %d public IP addresse(s) via AWS ConfigService", len(resources))

	if len(resources) == 0 || skipScan {
		log.Info("Skipping scan and exiting.")
		os.Exit(0)
	}

	publicIPs := lo.Map(resources, func(r Resource, index int) string { return r.PublicIP.String() })

	log.Debugf("List of public IPs to be scanned: %v", publicIPs)

	openPorts := make(map[string][]int) // map resourceID to a list of open ports

	options := runner.Options{
		Host: publicIPs,
		OnResult: func(hr *result.HostResult) {
			// lookup corresponding resource; should be one only with this public IP
			r := lo.Filter(resources, func(r Resource, index int) bool { return r.PublicIP.String() == hr.IP })[0]

			for _, p := range hr.Ports {

				openPorts[r.ID] = append(openPorts[r.ID], p.Port)

				log.Warnw(fmt.Sprintf("%s has open port %d  %s ", bold(hr.IP), p.Port, red("\uF071")), "resource_id", r.ID, "account", r.Account)

				// reverse ip lookup
				log.Debug("Reverse looking up ip address to get hostname")
				hostnames, err := lookupAddr(r.PublicIP)
				if err == nil {
					log.Infof("%s hostnames = %v", bold(hr.IP), hostnames)
				}

				// try to get instance id
				log.Debug("Trying to get associated instance id for network interface id")
				e := ec2.NewFromConfig(cfg)
				interfacesOutput, err := e.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
					NetworkInterfaceIds: []string{r.ID},
				})
				if err == nil {
					interfaces := interfacesOutput.NetworkInterfaces
					if len(interfaces) == 1 {
						log.Infof("%s is associated with instance ID %s", bold(hr.IP), *interfaces[0].Attachment.InstanceId)
					} else {
						log.Warnf("NetworkInterfaces returned = %d", len(interfaces))
					}
				} else {
					log.Error(err)
				}

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
	log.Debugf("Ports Top100 = %s", runner.NmapTop100)

	err = naabuRunner.RunEnumeration()
	if err != nil {
		log.Error(err)
	}

	log.Info("Finished all scanning")

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"IP Address", "Open Ports", "Resource ID", "Account ID"})
	for id, ports := range openPorts {
		r := lo.Filter(resources, func(r Resource, index int) bool { return r.ID == id })[0]
		t.AppendRow([]interface{}{r.PublicIP, ports, id, r.Account})
	}
	t.AppendSeparator()
	t.Render()

	return nil
}

func prettifyJSON(json string) string {
	f := prettyjson.NewFormatter()
	f.Indent = 0
	f.Newline = ""
	pretty, _ := f.Format([]byte(json))

	return string(pretty)
}

// lookupAddr performs a reverse lookup for the given address
func lookupAddr(ip net.IP) (name []string, err error) {
	reverse, err := net.LookupAddr(ip.String())
	if err != nil {
		return nil, err
	}

	return reverse, nil
}

// init initializes the terminal color functions
func init() {
	red = color.New(color.FgRed).SprintFunc()
	bold = color.New(color.Bold).SprintFunc()
	cyan = color.New(color.FgCyan).SprintFunc()
}
