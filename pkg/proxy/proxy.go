//
// Copyright 2016 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/policy"

	"github.com/braintree/manners"
	"github.com/op/go-logging"
	"github.com/vulcand/oxy/forward"
	"github.com/vulcand/route"
)

var (
	log = logging.MustGetLogger("cilium-proxy")
)

type Redirect struct {
	id       string
	FromPort uint16
	ToPort   uint16
	Rules    []policy.AuxRule
	source   ProxySource
	server   *manners.GracefulServer
	router   route.Router
}

func (r *Redirect) updateRules(rules []policy.AuxRule) {
	for _, v := range r.Rules {
		r.router.RemoveRoute(v.Expr)
	}

	r.Rules = make([]policy.AuxRule, len(rules))
	copy(r.Rules, rules)

	for _, v := range r.Rules {
		r.router.AddRoute(v.Expr, v)
	}
}

type ProxySource interface {
}

type Proxy struct {
	rangeMin       uint16
	rangeMax       uint16
	nextPort       uint16
	allocatedPorts map[uint16]*Redirect
	redirects      map[string]*Redirect
	mutex          sync.RWMutex
}

func NewProxy(minPort uint16, maxPort uint16) *Proxy {
	return &Proxy{
		rangeMin:       minPort,
		rangeMax:       maxPort,
		nextPort:       minPort,
		redirects:      make(map[string]*Redirect),
		allocatedPorts: make(map[uint16]*Redirect),
	}
}

func (p *Proxy) allocatePort() (uint16, error) {
	port := p.nextPort

	for {
		resPort := port
		port++
		if port >= p.rangeMax {
			port = p.rangeMin
		}

		if _, ok := p.allocatedPorts[resPort]; !ok {
			return resPort, nil
		}

		if port == p.nextPort {
			return 0, fmt.Errorf("no availabla proxy ports")
		}
	}
}

func generateURL(w http.ResponseWriter, req *http.Request, dport uint16) (*url.URL, error) {
	ip, port, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("Invalid remote address")
	}

	pIP := net.ParseIP(ip)
	if pIP == nil {
		return nil, fmt.Errorf("Unable to parse IP string")
	}

	sport, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse port string")
	}

	key := &Proxy4Key{
		SPort:   uint16(sport),
		DPort:   dport,
		Nexthdr: 6,
	}

	copy(key.SAddr[:], pIP.To4())

	log.Debugf("Looking up proxy %+v\n", key)

	val, err := LookupEgress4(key)
	if err != nil {
		return nil, fmt.Errorf("Unable to find proxy entry for %s: %s", key, err)
	}

	log.Debugf("Found proxy entry: %+v\n", val)

	newUrl := fmt.Sprintf("http://%s:%d%s", val.OrigDAddr.IP().String(), val.OrigDPort, req.URL)
	log.Debugf("New URL: %s\n", newUrl)

	out, err := url.ParseRequestURI(newUrl)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse url %s: %s", newUrl, err)
	}

	return out, nil
}

var gcOnce sync.Once

func (p *Proxy) CreateOrUpdateRedirect(l4 *policy.L4Filter, id string, source ProxySource) (*Redirect, error) {
	fwd, err := forward.New()
	if err != nil {
		return nil, err
	}

	if strings.ToLower(l4.Redirect) != "http" {
		return nil, fmt.Errorf("unknown L7 protocol \"%s\"", l4.Redirect)
	}

	for _, r := range l4.Rules {
		if !route.IsValid(r.Expr) {
			return nil, fmt.Errorf("invalid filter expression: %s", r.Expr)
		}
	}

	gcOnce.Do(func() {
		go func() {
			for {
				time.Sleep(time.Duration(10) * time.Second)
				if deleted := GC(); deleted > 0 {
					log.Debugf("Evicted %d entries from proxy table\n", deleted)
				}
			}
		}()
	})

	p.mutex.Lock()

	if r, ok := p.redirects[id]; ok {
		r.updateRules(l4.Rules)
		log.Debugf("updated existing proxy instance %+v", r)
		p.mutex.Unlock()
		return r, nil
	}

	to, err := p.allocatePort()
	if err != nil {
		p.mutex.Unlock()
		return nil, err
	}

	redir := &Redirect{
		id:       id,
		FromPort: uint16(l4.Port),
		ToPort:   to,
		source:   source,
		router:   route.New(),
	}

	redirect := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.Infof("New request: %+v | %+v\n", w, req)

		// Validate access to L4/L7 resource
		p.mutex.Lock()
		if len(redir.Rules) > 0 {
			rule, _ := redir.router.Route(req)
			if rule == nil {
				http.Error(w, fmt.Sprintf("Access denied, req = %+v", req), http.StatusForbidden)
				p.mutex.Unlock()
				return
			} else {
				ar := rule.(policy.AuxRule)
				log.Debugf("Allowing request based on rule %+v\n", ar)
			}
		}
		p.mutex.Unlock()

		// Reconstruct original URL used for the request
		if newURL, err := generateURL(w, req, to); err != nil {
			log.Errorf("%s\n", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} else {
			req.URL = newURL
		}

		fwd.ServeHTTP(w, req)
	})

	redir.server = manners.NewWithServer(&http.Server{
		Addr:    fmt.Sprintf(":%d", to),
		Handler: redirect,
	})

	redir.updateRules(l4.Rules)
	p.allocatedPorts[to] = redir
	p.redirects[id] = redir

	p.mutex.Unlock()

	log.Debugf("Created new proxy intance %+v", redir)

	go func() {
		redir.server.ListenAndServe()
	}()

	return redir, nil
}

func (p *Proxy) GetRedirect(id string) *Redirect {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return p.redirects[id]
}

func (p *Proxy) RemoveRedirect(id string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if r, ok := p.redirects[id]; !ok {
		return fmt.Errorf("unable to find redirect %s", id)
	} else {
		r.server.Close()

		p.redirects[r.id] = nil
		p.allocatedPorts[r.ToPort] = nil
	}

	return nil
}
