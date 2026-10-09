//go:build unix

package noise

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// recordingFlows is a FlowSink that records every stored flow for assertions.
type recordingFlows struct {
	mu        sync.Mutex
	seq       int
	flows     []*types.Flow
	byID      map[string]*types.Flow
	completed map[string]bool
}

func newRecordingFlows() *recordingFlows {
	return &recordingFlows{byID: map[string]*types.Flow{}, completed: map[string]bool{}}
}

func (f *recordingFlows) Store(fl *types.Flow) string {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.seq++
	id := "flow" + strconv.Itoa(f.seq)
	fl.FlowID = id
	f.flows = append(f.flows, fl)
	f.byID[id] = fl
	return id
}

func (f *recordingFlows) Complete(id string, resp *types.Message, _ time.Time, _ map[string]any) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	fl, ok := f.byID[id]
	if ok {
		f.completed[id] = true
		if resp != nil {
			fl.Response = resp
		}
	}
	return ok
}

func (f *recordingFlows) wasCompleted(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.completed[id]
}

// completedSnapshot clones the completed-flow set for assertions.
func (f *recordingFlows) completedSnapshot() map[string]bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return maps.Clone(f.completed)
}

func (f *recordingFlows) SetInvokedBy(string, string) bool { return true }

func (f *recordingFlows) Get(id string) (*types.Flow, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	fl, ok := f.byID[id]
	return fl, ok
}

func (f *recordingFlows) ShouldCapture(*types.Flow) bool { return true }

func (f *recordingFlows) list() []*types.Flow {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.flows)
}

// captureNone excludes every flow, standing in for an operator capture filter that
// drops the tailscale.* tags. Recording delegates otherwise work normally.
type captureNone struct{ *recordingFlows }

func (captureNone) ShouldCapture(*types.Flow) bool { return false }

// stubRules is a RuleSource returning a fixed rule snapshot.
type stubRules struct{ rules []wire.Rule }

func (r stubRules) RuleSnapshot(string) []wire.Rule { return r.rules }

const testInstanceID = "00000000-0000-4000-8000-000000000001"

// testHandler starts a standalone host with the given flow sink, core service, rule
// source, and host hooks, dials a real sidecar connection, and returns a handler wired to it.
func testHandler(t *testing.T, cfg *ControlConfig, flows scsidecar.FlowSink, core scsidecar.CoreService, rules scsidecar.RuleSource, hostCfg scsidecar.Config) *Handler {
	t.Helper()

	socket := filepath.Join(t.TempDir(), "sidecar.sock")
	hostCfg.Socket = socket
	mgr := scsidecar.NewManager(hostCfg, &protocol.Registry{}, flows, core, rules)
	lst, err := scsidecar.NewListener(t.Context(), hostCfg, mgr)
	require.NoError(t, err)
	go func() { _ = lst.Serve() }()
	t.Cleanup(func() { _ = lst.Close(context.Background()) })

	reg := sidecar.Registration{Name: "sidescale.test", InstanceID: testInstanceID, Resume: true}
	conn, err := sidecar.Dial(t.Context(), socket, reg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	router := sidecar.NewStreamRouter(conn)
	h := NewHandler(t.Context(), conn, router, cfg, "sidescale.test", key.NewMachine(), func(string) (key.MachinePrivate, error) { return key.NewMachine(), nil })
	close(h.setupDone) // harness handlers are post-setup; Setup is exercised separately
	return h
}

func defaultControlConfig() (ControlConfig, error) {
	var c ControlConfig
	c.ApplyDefaults()
	return c, nil
}

// noopCore is a CoreService that declines every tool.
type noopCore struct{}

func (noopCore) CoreInvoke(context.Context, string, json.RawMessage) (string, bool, error) {
	return "", false, errors.New("unexpected core invoke")
}
func (noopCore) CoreToolNames() []string { return nil }

// fakeCore is a CoreService that answers proxy_respond_add/delete and records the
// params and call order of each tool invocation.
type fakeCore struct {
	mu      sync.Mutex
	invoked map[string][]json.RawMessage
	order   []string
}

func newFakeCore() *fakeCore { return &fakeCore{invoked: map[string][]json.RawMessage{}} }

func (c *fakeCore) CoreInvoke(_ context.Context, tool string, params json.RawMessage) (string, bool, error) {
	c.mu.Lock()
	c.invoked[tool] = append(c.invoked[tool], params)
	c.order = append(c.order, tool)
	c.mu.Unlock()
	switch tool {
	case "proxy_respond_add":
		return `{"responder_id":"resp1"}`, false, nil
	case "proxy_respond_delete":
		return `{}`, false, nil
	default:
		return "", false, fmt.Errorf("unknown tool: %s", tool)
	}
}

func (c *fakeCore) CoreToolNames() []string { return nil }

func (c *fakeCore) params(tool string) json.RawMessage {
	c.mu.Lock()
	defer c.mu.Unlock()

	calls := c.invoked[tool]
	if len(calls) == 0 {
		return nil
	}
	return calls[len(calls)-1]
}

// allParams returns every recorded params payload for tool, in call order.
func (c *fakeCore) allParams(tool string) []json.RawMessage {
	c.mu.Lock()
	defer c.mu.Unlock()

	return slices.Clone(c.invoked[tool])
}

// calls returns the ordered tool names CoreInvoke saw.
func (c *fakeCore) calls() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return slices.Clone(c.order)
}

// failAddCore fails proxy_respond_add when its params name failHost, standing in for
// a host-side registration refusal mid-setup.
type failAddCore struct {
	*fakeCore
	failHost string
}

func (c *failAddCore) CoreInvoke(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
	if tool == "proxy_respond_add" && strings.Contains(string(params), c.failHost) {
		return "", false, errors.New("responder add refused")
	}
	return c.fakeCore.CoreInvoke(ctx, tool, params)
}

// fakeKeyResponse returns a NativeHTTPSend hook that answers /key with the given server public key.
func fakeKeyResponse(realKey key.MachinePublic) func(context.Context, wire.SidecarSendParams, string) (wire.SidecarSendResult, *wire.Error) {
	body := []byte(`{"publicKey":"` + realKey.String() + `"}`)
	return func(context.Context, wire.SidecarSendParams, string) (wire.SidecarSendResult, *wire.Error) {
		return wire.SidecarSendResult{Response: &wire.FlowMessage{StatusCode: 200, Body: body}}, nil
	}
}

// fakeKeyResponseByHost returns a NativeHTTPSend hook that answers /key with a distinct
// server key per URL host, standing in for independent upstream coordinators.
func fakeKeyResponseByHost(keys map[string]key.MachinePublic) func(context.Context, wire.SidecarSendParams, string) (wire.SidecarSendResult, *wire.Error) {
	return func(_ context.Context, p wire.SidecarSendParams, _ string) (wire.SidecarSendResult, *wire.Error) {
		var target struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(p.Target, &target); err != nil {
			return wire.SidecarSendResult{}, wire.NewError(1, "bad target")
		}
		u, err := url.Parse(target.URL)
		if err != nil {
			return wire.SidecarSendResult{}, wire.NewError(1, "bad url")
		}
		pub, ok := keys[u.Hostname()]
		if !ok {
			return wire.SidecarSendResult{}, wire.NewError(1, "no key for host "+u.Hostname())
		}
		body := []byte(`{"publicKey":"` + pub.String() + `"}`)
		return wire.SidecarSendResult{Response: &wire.FlowMessage{StatusCode: 200, Body: body}}, nil
	}
}
