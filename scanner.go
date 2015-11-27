package awscan

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/autoscaling"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/rds"
)

type EC2Scanner interface {
	GetInstance(string) (*ec2.Reservation, error)
	ScanSecurityGroups() ([]*ec2.SecurityGroup, error)
	ScanSecurityGroupInstances(string) ([]*ec2.Reservation, error)
	GetLoadBalancer(string) (*elb.LoadBalancerDescription, error)
	ScanLoadBalancers() ([]*elb.LoadBalancerDescription, error)
	ScanRDS() ([]*rds.DBInstance, error)
	ScanRDSSecurityGroups() ([]*rds.DBSecurityGroup, error)
	ScanAutoScalingGroups() ([]*autoscaling.Group, error)
}

type eC2ScannerImpl struct {
	session *session.Session
}

type Config struct {
	AccessKeyId string
	SecretKey   string
	Region      string
}

func NewScanner(sess *session.Session) EC2Scanner {
	return &eC2ScannerImpl{
		session: sess,
	}
}

func (s *eC2ScannerImpl) getSession() *session.Session {
	return s.session
}

func (s *eC2ScannerImpl) getEC2Client() *ec2.EC2 {
	return ec2.New(s.getSession())
}

func (s *eC2ScannerImpl) getELBClient() *elb.ELB {
	return elb.New(s.getSession())
}

func (s *eC2ScannerImpl) getRDSClient() *rds.RDS {
	return rds.New(s.getSession())
}

func (s *eC2ScannerImpl) getAutoScalingClient() *autoscaling.AutoScaling {
	return autoscaling.New(s.getSession())
}

func (s *eC2ScannerImpl) GetInstance(instanceId string) (*ec2.Reservation, error) {
	client := s.getEC2Client()
	resp, err := client.DescribeInstances(&ec2.DescribeInstancesInput{InstanceIds: []*string{&instanceId}})
	if err != nil {
		if len(resp.Reservations) > 1 {
			return nil, fmt.Errorf("Received multiple reservations for instance id: %v, %v", instanceId, resp)
		}
		return nil, err
	}

	// InstanceId to Reservation mappings are 1-to-1
	reservation := resp.Reservations[0]

	return reservation, nil
}

func (s *eC2ScannerImpl) ScanSecurityGroups() ([]*ec2.SecurityGroup, error) {
	client := s.getEC2Client()
	resp, err := client.DescribeSecurityGroups(nil)
	if err != nil {
		return nil, err
	}
	return resp.SecurityGroups, nil
}

func (s *eC2ScannerImpl) ScanSecurityGroupInstances(groupId string) ([]*ec2.Reservation, error) {
	client := s.getEC2Client()
	var grs []*string = []*string{&groupId}
	var reservations []*ec2.Reservation

	filters := []*ec2.Filter{&ec2.Filter{Name: aws.String("instance.group-id"), Values: grs}}

	err := client.DescribeInstancesPages(&ec2.DescribeInstancesInput{Filters: filters}, func(resp *ec2.DescribeInstancesOutput, lastPage bool) bool {
		for _, res := range resp.Reservations {
			reservations = append(reservations, res)
		}
		if lastPage {
			return false
		}
		return true
	})

	if err != nil {
		return nil, err
	}

	return reservations, nil
}

func (s *eC2ScannerImpl) GetLoadBalancer(elbId string) (*elb.LoadBalancerDescription, error) {
	client := s.getELBClient()
	input := &elb.DescribeLoadBalancersInput{
		LoadBalancerNames: []*string{aws.String(elbId)},
	}
	resp, err := client.DescribeLoadBalancers(input)
	if err != nil {
		return nil, err
	}

	return resp.LoadBalancerDescriptions[0], nil
}

func (s *eC2ScannerImpl) ScanLoadBalancers() ([]*elb.LoadBalancerDescription, error) {
	client := s.getELBClient()
	resp, err := client.DescribeLoadBalancers(nil)
	if err != nil {
		return nil, err
	}
	return resp.LoadBalancerDescriptions, nil
}

func (s *eC2ScannerImpl) ScanRDS() ([]*rds.DBInstance, error) {
	client := s.getRDSClient()
	resp, err := client.DescribeDBInstances(nil)
	if err != nil {
		return nil, err
	}
	return resp.DBInstances, nil
}

func (s *eC2ScannerImpl) ScanRDSSecurityGroups() ([]*rds.DBSecurityGroup, error) {
	client := s.getRDSClient()
	resp, err := client.DescribeDBSecurityGroups(nil)
	if err != nil {
		return nil, err
	}
	return resp.DBSecurityGroups, nil
}

func (s *eC2ScannerImpl) ScanAutoScalingGroups() ([]*autoscaling.Group, error) {
	client := s.getAutoScalingClient()
	var asgs []*autoscaling.Group

	err := client.DescribeAutoScalingGroupsPages(&autoscaling.DescribeAutoScalingGroupsInput{}, func(resp *autoscaling.DescribeAutoScalingGroupsOutput, lastPage bool) bool {
		for _, asg := range resp.AutoScalingGroups {
			asgs = append(asgs, asg)
		}
		if lastPage {
			return false
		}
		return true
	})

	if err != nil {
		return nil, err
	}

	return asgs, nil
}
