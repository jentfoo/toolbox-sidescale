package adapter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveUpstream(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		host          string
		override      string
		hosts         []string
		defaultScheme string
		want          UpstreamTarget
	}{
		{"no_override_default_https", "ctrl.example", "", nil, "https", UpstreamTarget{Host: "ctrl.example", Port: 443, Scheme: "https"}},
		{"no_override_default_http", "ctrl.example", "", nil, "http", UpstreamTarget{Host: "ctrl.example", Port: 80, Scheme: "http"}},
		{"no_override_host_list_port", "ctrl.example", "", []string{"ctrl.example:8443"}, "https", UpstreamTarget{Host: "ctrl.example", Port: 8443, Scheme: "https"}},
		{"no_override_host_port_stripped", "ctrl.example:80", "", []string{"ctrl.example:8443"}, "https", UpstreamTarget{Host: "ctrl.example", Port: 8443, Scheme: "https"}},
		{"no_override_host_list_http_port", "ctrl.example", "", []string{"ctrl.example:8080"}, "http", UpstreamTarget{Host: "ctrl.example", Port: 8080, Scheme: "http"}},
		{"override_bare_host", "ctrl.example", "1.2.3.4", nil, "http", UpstreamTarget{Host: "1.2.3.4", Port: 80, Scheme: "http"}},
		{"override_bare_hostport", "ctrl.example", "1.2.3.4:8443", nil, "https", UpstreamTarget{Host: "1.2.3.4", Port: 8443, Scheme: "https"}},
		{"override_url_http_default_port", "ctrl.example", "http://1.2.3.4", nil, "https", UpstreamTarget{Host: "1.2.3.4", Port: 80, Scheme: "http"}},
		{"override_url_http_explicit_port", "ctrl.example", "http://1.2.3.4:8080", nil, "https", UpstreamTarget{Host: "1.2.3.4", Port: 8080, Scheme: "http"}},
		{"override_url_https_default_port", "ctrl.example", "https://1.2.3.4", nil, "http", UpstreamTarget{Host: "1.2.3.4", Port: 443, Scheme: "https"}},
		{"override_url_https_explicit_port", "ctrl.example", "https://1.2.3.4:9443", nil, "http", UpstreamTarget{Host: "1.2.3.4", Port: 9443, Scheme: "https"}},
		{"override_wins_over_host_list", "ctrl.example", "1.2.3.4:9443", []string{"ctrl.example:8443"}, "https", UpstreamTarget{Host: "1.2.3.4", Port: 9443, Scheme: "https"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ResolveUpstream(tc.host, tc.override, tc.hosts, tc.defaultScheme))
		})
	}
}
