package awscan

import (
	"sync"
)

type Discoverer interface {
	Discover() <-chan Event
}

type Event struct {
	Result interface{}
	Err    error
}

type discoverer struct {
	wg        *sync.WaitGroup
	sc        EC2Scanner
	discoChan chan Event
}

func NewDiscoverer(s EC2Scanner) Discoverer {
	disco := &discoverer{
		sc:        s,
		wg:        &sync.WaitGroup{},
		discoChan: make(chan Event, 128),
	}
	return disco
}

func (d *discoverer) Discover() <-chan Event {
	go d.scanLoadBalancers()
	go d.scanRDS()
	go d.scanRDSSecurityGroups()
	go d.scanSecurityGroups()
	go func() {
		d.wg.Wait()
		close(d.discoChan)
	}()
	return d.discoChan
}

func (d *discoverer) scanSecurityGroups() {
	d.wg.Add(1)
	if sgs, err := d.sc.ScanSecurityGroups(); err != nil {
		d.discoChan <- Event{nil, err}
	} else {
		for _, sg := range sgs {
			if sg != nil {
				d.discoChan <- Event{sg, nil}
				if sg.GroupId != nil {
					if reservations, err := d.sc.ScanSecurityGroupInstances(*sg.GroupId); err != nil {
						d.discoChan <- Event{nil, err}
					} else {
						for _, reservation := range reservations {
							if reservation != nil {
								for _, instance := range reservation.Instances {
									if instance != nil {
										d.discoChan <- Event{instance, nil}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	d.wg.Done()
}

func (d *discoverer) scanLoadBalancers() {
	d.wg.Add(1)
	if lbs, err := d.sc.ScanLoadBalancers(); err != nil {
		d.discoChan <- Event{nil, err}
	} else {
		for _, lb := range lbs {
			if lb != nil {
				d.discoChan <- Event{lb, nil}
			}
		}
	}
	d.wg.Done()
}

func (d *discoverer) scanRDS() {
	d.wg.Add(1)
	if rdses, err := d.sc.ScanRDS(); err != nil {
		d.discoChan <- Event{nil, err}
	} else {
		for _, rdsInst := range rdses {
			if rdsInst != nil {
				d.discoChan <- Event{rdsInst, nil}
			}
		}
	}
	d.wg.Done()
}

func (d *discoverer) scanRDSSecurityGroups() {
	d.wg.Add(1)
	if rdssgs, err := d.sc.ScanRDSSecurityGroups(); err != nil {
		d.discoChan <- Event{nil, err}
	} else {
		for _, rdssg := range rdssgs {
			if rdssg != nil {
				d.discoChan <- Event{rdssg, nil}
			}
		}
	}
	d.wg.Done()
}
