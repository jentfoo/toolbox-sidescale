package adapter

import (
	"net/url"
	"strings"

	"github.com/go-appsec/toolbox/pkg/addr"
)

// UpstreamTarget is a resolved upstream dial target.
type UpstreamTarget struct {
	Host   string
	Port   int
	Scheme string // "http" or "https"
}

// ResolveUpstream resolves host to an upstream dial target. override, when non-empty, supplies
// the target as a "scheme://host[:port]" URL or a bare "host[:port]" authority; otherwise host is
// used and its port is recovered from a matching entry in hosts. defaultScheme selects the transport
// and default port when neither the override URL nor an authority carries them.
func ResolveUpstream(host, override string, hosts []string, defaultScheme string) UpstreamTarget {
	if override == "" {
		host, port := addr.Parse(host, defaultScheme)
		for _, h := range hosts {
			if hh, p := addr.Parse(h, defaultScheme); strings.EqualFold(hh, host) {
				port = p
				break
			}
		}
		return UpstreamTarget{Host: host, Port: port, Scheme: defaultScheme}
	}
	if strings.Contains(override, "://") {
		if u, err := url.Parse(override); err == nil && u.Host != "" {
			h, p := addr.Parse(u.Host, u.Scheme)
			return UpstreamTarget{Host: h, Port: p, Scheme: u.Scheme}
		}
	}
	h, p := addr.Parse(override, defaultScheme)
	return UpstreamTarget{Host: h, Port: p, Scheme: defaultScheme}
}
