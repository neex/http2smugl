package main

import (
	"fmt"
	"net"
	"sync"
)

type DNSCache struct {
	m     sync.Mutex
	cache map[string]*cacheEntry
}

var DefaultDNSCache = &DNSCache{
	cache: make(map[string]*cacheEntry),
}

func (c *DNSCache) Lookup(name string) (net.IP, error) {
	return c.getEntry(name).lookupAndFill(name)
}

func (c *DNSCache) getEntry(name string) *cacheEntry {
	c.m.Lock()
	defer c.m.Unlock()
	if e, ok := c.cache[name]; ok {
		return e
	}
	e := new(cacheEntry)
	c.cache[name] = e
	return e
}

type cacheEntry struct {
	m  sync.Mutex
	ip net.IP
}

func (e *cacheEntry) lookupAndFill(name string) (net.IP, error) {
	e.m.Lock()
	defer e.m.Unlock()
	if e.ip != nil {
		return e.ip, nil
	}

	ips, err := net.LookupIP(name)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no such host: %v", name)
	}
	var bestIP net.IP
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 != nil {
			bestIP = ip4
		}
		if bestIP == nil {
			bestIP = ip
		}
	}
	e.ip = bestIP
	return bestIP, nil
}
