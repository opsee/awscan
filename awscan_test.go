package awscan

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go/service/autoscaling"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

const (
	count = 200
)

type testScanner struct {
	reservations      []*ec2.Reservation
	securityGroups    []*ec2.SecurityGroup
	loadBalancers     []*elb.LoadBalancerDescription
	dbInstances       []*rds.DBInstance
	dbSecurityGroups  []*rds.DBSecurityGroup
	autoscalingGroups []*autoscaling.Group
	routeTables       []*ec2.RouteTable
	subnets           []*ec2.Subnet
}

func TestDiscover(t *testing.T) {
	scanner := newTestScanner(t)
	discoverer := NewDiscoverer(scanner)

	for event := range discoverer.Discover() {
		assert.Nil(t, event.Err)
		assert.NotNil(t, event.Result)
	}
}

func newTestScanner(t *testing.T) *testScanner {
	ts := &testScanner{
		reservations:      loadReservations(t),
		securityGroups:    loadSecurityGroups(t),
		loadBalancers:     loadLoadBalancers(t),
		dbInstances:       loadRdsInstances(t),
		dbSecurityGroups:  loadRdsSecurityGroups(t),
		autoscalingGroups: loadAutoScalingGroups(t),
		routeTables:       loadRouteTables(t),
		subnets:           loadSubnets(t),
	}

	t.Logf("reservations: %d", len(ts.reservations))
	t.Logf("securityGroups: %d", len(ts.securityGroups))
	t.Logf("loadBalancers: %d", len(ts.loadBalancers))
	t.Logf("dbInstances: %d", len(ts.dbInstances))
	t.Logf("dbSecurityGroups: %d", len(ts.dbSecurityGroups))
	t.Logf("autoscalingGroups: %d", len(ts.autoscalingGroups))
	t.Logf("routeTables: %d", len(ts.routeTables))
	t.Logf("subnets: %d", len(ts.subnets))

	return ts
}

func (ts *testScanner) GetInstance(instID string) (*ec2.Reservation, error) {
	return ts.reservations[0], nil
}

func (ts *testScanner) ScanSecurityGroups() ([]*ec2.SecurityGroup, error) {
	return ts.securityGroups, nil
}

func (ts *testScanner) ScanSecurityGroupInstances(sgID string) ([]*ec2.Reservation, error) {
	return ts.reservations, nil
}

func (ts *testScanner) GetLoadBalancer(string) (*elb.LoadBalancerDescription, error) {
	return ts.loadBalancers[0], nil
}

func (ts *testScanner) ScanLoadBalancers() ([]*elb.LoadBalancerDescription, error) {
	return ts.loadBalancers, nil
}

func (ts *testScanner) ScanRDS() ([]*rds.DBInstance, error) {
	return ts.dbInstances, nil
}

func (ts *testScanner) ScanRDSSecurityGroups() ([]*rds.DBSecurityGroup, error) {
	return ts.dbSecurityGroups, nil
}

func (ts *testScanner) ScanAutoScalingGroups() ([]*autoscaling.Group, error) {
	return ts.autoscalingGroups, nil
}

func (ts *testScanner) ScanRouteTables() ([]*ec2.RouteTable, error) {
	return ts.routeTables, nil
}

func (ts *testScanner) ScanSubnets() ([]*ec2.Subnet, error) {
	return ts.subnets, nil
}

func loadRdsSecurityGroups(t *testing.T) []*rds.DBSecurityGroup {
	c := make([]*rds.DBSecurityGroup, count)

	for i := 0; i < count; i++ {
		c = append(c, &rds.DBSecurityGroup{})
	}

	return c
}

func loadRdsInstances(t *testing.T) []*rds.DBInstance {
	c := make([]*rds.DBInstance, count)

	for i := 0; i < count; i++ {
		c = append(c, &rds.DBInstance{})
	}

	return c
}

func loadAutoScalingGroups(t *testing.T) []*autoscaling.Group {
	c := make([]*autoscaling.Group, count)

	for i := 0; i < count; i++ {
		c = append(c, &autoscaling.Group{})
	}

	return c
}

func loadLoadBalancers(t *testing.T) []*elb.LoadBalancerDescription {
	c := make([]*elb.LoadBalancerDescription, count)

	for i := 0; i < count; i++ {
		c = append(c, &elb.LoadBalancerDescription{})
	}

	return c
}

func loadSecurityGroups(t *testing.T) []*ec2.SecurityGroup {
	c := make([]*ec2.SecurityGroup, count)

	for i := 0; i < count; i++ {
		c = append(c, &ec2.SecurityGroup{})
	}

	return c
}

func loadReservations(t *testing.T) []*ec2.Reservation {
	c := make([]*ec2.Reservation, count)

	for i := 0; i < count; i++ {
		c = append(c, &ec2.Reservation{})
	}

	return c
}

func loadRouteTables(t *testing.T) []*ec2.RouteTable {
	c := make([]*ec2.RouteTable, count)

	for i := 0; i < count; i++ {
		c = append(c, &ec2.RouteTable{})
	}

	return c
}

func loadSubnets(t *testing.T) []*ec2.Subnet {
	c := make([]*ec2.Subnet, count)

	for i := 0; i < count; i++ {
		c = append(c, &ec2.Subnet{})
	}

	return c
}

func readJson(filePath string, thing interface{}) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)

	err = decoder.Decode(thing)
	return err
}
