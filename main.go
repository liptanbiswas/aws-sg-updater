package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	externalip "github.com/GlenDC/go-external-ip"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

type sgGroupID []string

var groupIds sgGroupID
var tagexists int

func revokeOldSecurityGroupRule(c *ec2.EC2, groupid *string, oldrange *ec2.IpPermission) {

	req := &ec2.RevokeSecurityGroupIngressInput{
		GroupId:       groupid,
		IpPermissions: []*ec2.IpPermission{oldrange},
	}
	_, err := c.RevokeSecurityGroupIngress(req)

	if err != nil {
		fmt.Errorf(
			"Error revoking security group %s rules: %s",
			*groupid, err)
	}
	fmt.Printf("Successfully removed Security Group rule for %s\n", *groupid)
}

func addNewSecurityGroupRule(c *ec2.EC2, groupid *string, tag *string, wanip net.IP) {

	if wanip.To4() != nil {
		wancidr := wanip.String() + "/32"
		req := &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId: groupid,
			IpPermissions: []*ec2.IpPermission{
				(&ec2.IpPermission{}).
					SetIpProtocol("-1").
					SetIpRanges([]*ec2.IpRange{
						{CidrIp: aws.String(wancidr), Description: tag},
					}),
			},
		}
		_, err := c.AuthorizeSecurityGroupIngress(req)

		if err != nil {
			fmt.Errorf(
				"Error Adding security group %s rules: %s",
				*groupid, err)
		}
		fmt.Printf("Successfully added Security Group for tag %s and IP %s\n", *tag, wancidr)
	} else {
		wancidr := wanip.String() + "/128"
		req := &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId: groupid,
			IpPermissions: []*ec2.IpPermission{
				(&ec2.IpPermission{}).
					SetIpProtocol("-1").
					SetIpv6Ranges([]*ec2.Ipv6Range{
						{CidrIpv6: aws.String(wancidr), Description: tag},
					}),
			},
		}
		_, err := c.AuthorizeSecurityGroupIngress(req)

		if err != nil {
			fmt.Errorf(
				"Error Adding security group %s rules: %s",
				*groupid, err)
		}
		fmt.Printf("Successfully added Security Group for tag %s and IP %s\n", *tag, wancidr)
	}
}

func (i *sgGroupID) String() string {
	return ""
}

func (i *sgGroupID) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func run(groupIds sgGroupID, tag *string) {
	consensus := externalip.DefaultConsensus(nil, nil)
	wanip, err := consensus.ExternalIP()
	if err != nil {
		exitErrorf("Error getting IP address.")
	}

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-west-2")},
	)

	svc := ec2.New(sess)

	result, err := svc.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		GroupIds: aws.StringSlice(groupIds),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidGroupId.Malformed":
				fallthrough
			case "InvalidGroup.NotFound":
				exitErrorf("%s.", aerr.Message())
			}
		}
		exitErrorf("Unable to get descriptions for security groups, %v", err)
	}
	for _, group := range result.SecurityGroups {
		fmt.Printf("Checking Security Group ID : %s\n", *group.GroupId)
		for _, ingress := range group.IpPermissions {
			if ingress.Ipv6Ranges != nil {
				if ingress.Ipv6Ranges[0].Description != nil && *ingress.Ipv6Ranges[0].Description == *tag {
					tagexists = 1
					awsip, _, err := net.ParseCIDR(*ingress.Ipv6Ranges[0].CidrIpv6)

					if err != nil {
						exitErrorf("Unable to Parse IP address.")
					}
					if net.IP.Equal(awsip, wanip) {
						fmt.Printf("IP on aws for tag %s matched with wan IP %s\n", *tag, wanip)
					} else {
						fmt.Printf("IP on aws for tag %s not matched with wan IP %s\n", *tag, wanip)
						fmt.Printf("Revoking Old security group rule.\n")
						revokeOldSecurityGroupRule(svc, group.GroupId, ingress)
						fmt.Printf("Adding New security group rule.\n")
						addNewSecurityGroupRule(svc, group.GroupId, tag, wanip)
					}
				}
			}
			if ingress.IpRanges != nil {
				if ingress.IpRanges[0].Description != nil && *ingress.IpRanges[0].Description == *tag {
					tagexists = 1
					awsip, _, err := net.ParseCIDR(*ingress.IpRanges[0].CidrIp)

					if err != nil {
						exitErrorf("Unable to Parse IP address.")
					}
					if net.IP.Equal(awsip, wanip) {
						fmt.Printf("IP on aws for tag %s matched with wan IP %s\n", *tag, wanip)
					} else {
						fmt.Printf("IP on aws for tag %s not matched with wan IP %s\n", *tag, wanip)
						fmt.Printf("Revoking Old security group rule.")
						revokeOldSecurityGroupRule(svc, group.GroupId, ingress)
						fmt.Printf("Adding New security group rule.\n")
						addNewSecurityGroupRule(svc, group.GroupId, tag, wanip)
					}
				}
			}
		}
		if tagexists == 0 && *tag != "" {
			fmt.Printf("Security Group Rule for tag %s does not exist, creating it.\n", *tag)
			addNewSecurityGroupRule(svc, group.GroupId, tag, wanip)
		}
	}
}

func exitErrorf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func main() {
	flag.Var(&groupIds, "i", "AWS Security Group IDs.")
	tag := flag.String("t", "", "Tag name for identifying security group rule.")
	flag.Parse()

	if *tag == "" || groupIds == nil {
		fmt.Println("Usages: ./aws-sg-group")
		flag.PrintDefaults()
		os.Exit(1)
	}
	for {
		run(groupIds, tag)
		fmt.Println(time.Now().Format(time.RFC1123), "Sleeping for 300 seconds.")
		time.Sleep(300 * time.Second)
	}
}
