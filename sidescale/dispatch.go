package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/toolbox/pkg/addr"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/derp"
	"github.com/jentfoo/toolbox-sidescale/sidescale/noise"
)

const (
	ts2021Path = "/ts2021"
	derpPath   = "/derp"
)

// streamSurface is a protocol surface the dispatcher hands an accepted stream to.
type streamSurface interface {
	ServeStream(ctx context.Context, sc *sidecar.StreamConn)
}

// dispatcher is the single sidecar.Handler. The embedded router supplies the stream
// callbacks; acceptLoop routes each opened stream to the Noise or DERP surface.
type dispatcher struct {
	*sidecar.StreamRouter

	conn        *sidecar.Conn
	cfg         Config
	noise       *noise.Handler
	derp        *derp.Handler // nil when control-only
	controlHost string
	derpHosts   map[string]struct{} // lowercased host parts of cfg.Derp.DerpHosts
}

func newDispatcher(conn *sidecar.Conn, router *sidecar.StreamRouter, cfg Config, nh *noise.Handler, dh *derp.Handler) *dispatcher {
	// addr.Parse lowercases host so comparisons are case-insensitive
	controlHost, _ := addr.Parse(cfg.Control.ControlHosts[0], "https")
	var derpHosts map[string]struct{}
	if cfg.Derp != nil {
		derpHosts = bulk.SliceToSetBy(func(h string) string {
			host, _ := addr.Parse(h, "https")
			return host
		}, cfg.Derp.DerpHosts)
	}
	return &dispatcher{
		StreamRouter: router,
		conn:         conn,
		cfg:          cfg,
		noise:        nh,
		derp:         dh,
		controlHost:  controlHost,
		derpHosts:    derpHosts,
	}
}

// acceptLoop routes each opened stream to its surface until the conn closes.
func (d *dispatcher) acceptLoop(ctx context.Context) {
	for {
		sc, err := d.Accept(ctx)
		if err != nil {
			return
		}
		surface := d.routeOpen(sc.Open())
		if surface == nil {
			_ = sc.Close()
			continue
		}
		go surface.ServeStream(ctx, sc)
	}
}

// routeOpen selects the surface for an opened stream by path, or by config + host for
// a pathless early_claim. It returns nil when no surface claims the stream.
func (d *dispatcher) routeOpen(p wire.StreamOpenParams) streamSurface {
	switch {
	case p.Path == ts2021Path:
		return d.noise
	case p.Path == derpPath && d.derp != nil:
		return d.derp
	case p.Path == "":
		host, _ := addr.Parse(p.Host, "https")
		if d.derp != nil && d.cfg.Derp.RelayMode == derp.RelayModeTerminate {
			if _, ok := d.derpHosts[host]; ok {
				return d.derp
			}
		}
		if d.cfg.Control.KeyStrategy == noise.KeyStrategySubstitute &&
			d.cfg.Control.KeySubstitution == noise.KeySubSidecarTLS &&
			host == d.controlHost {
			return d.noise
		}
	}
	return nil
}

func (d *dispatcher) OnInvokeTool(p wire.InvokeToolParams) (wire.InvokeToolResult, error) {
	switch {
	case p.Name == noise.InjectToolName:
		return d.noise.OnInvokeTool(p)
	case p.Name == derp.InjectToolName && d.derp != nil:
		return d.derp.OnInvokeTool(p)
	}
	return wire.InvokeToolResult{}, fmt.Errorf("invoke_tool: unknown tool %q", p.Name)
}

func (d *dispatcher) OnSidecarSend(p wire.SidecarSendParams) (wire.SidecarSendResult, error) {
	// a replay needs its source flow inlined; sectool sends FlowID-only on a sink miss, and
	// neither surface can route or replay it without the flow's protocol tag / request
	if p.Flow == nil && p.FlowID != "" {
		return wire.SidecarSendResult{}, fmt.Errorf("sidecar_send: source flow %q not inlined; re-issue the replay", p.FlowID)
	}
	if d.derp != nil {
		if p.Flow != nil && strings.HasPrefix(p.Flow.ProtocolTag, "tailscale.derp.") {
			return d.derp.OnSidecarSend(p)
		}
		if p.Flow == nil && p.FlowID == "" && derpShapedSend(p) {
			return d.derp.OnSidecarSend(p)
		}
	}
	return d.noise.OnSidecarSend(p)
}

// derpShapedSend reports whether a no-base-flow send carries a DERP injection payload.
func derpShapedSend(p wire.SidecarSendParams) bool {
	// DERP and Noise injection schemas are disjoint (frame vs endpoint); the frame field disambiguates
	raw := p.Payload
	if len(raw) == 0 {
		raw = p.Target
	}
	if len(raw) == 0 {
		return false
	}
	var probe struct {
		Frame string `json:"frame"`
	}
	return json.Unmarshal(raw, &probe) == nil && probe.Frame != ""
}
