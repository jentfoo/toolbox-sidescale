//go:build unix

package derp

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-analyze/bulk"
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

func (f *recordingFlows) frameFlows() []*types.Flow {
	return bulk.SliceFilter(func(fl *types.Flow) bool {
		return fl.ProtocolTag == frameProtocolTag
	}, f.list())
}

// stubRules is a RuleSource returning a fixed rule snapshot.
type stubRules struct{ rules []wire.Rule }

func (r stubRules) RuleSnapshot(string) []wire.Rule { return r.rules }

// noopCore declines every core tool.
type noopCore struct{}

func (noopCore) CoreInvoke(context.Context, string, json.RawMessage) (string, bool, error) {
	return "", false, errors.New("unexpected core invoke")
}
func (noopCore) CoreToolNames() []string { return nil }

const testInstanceID = "00000000-0000-4000-8000-000000000002"

// testHandler stands up a sidecar host with the given flow sink and rules, dials a real
// sidecar connection, and returns a DERP handler wired to it.
func testHandler(t *testing.T, cfg *DerpConfig, flows scsidecar.FlowSink, rules scsidecar.RuleSource) *Handler {
	t.Helper()

	cfg.ApplyDefaults()
	socket := filepath.Join(t.TempDir(), "sidecar.sock")
	hostCfg := scsidecar.Config{Socket: socket}
	mgr := scsidecar.NewManager(hostCfg, &protocol.Registry{}, flows, noopCore{}, rules)
	lst, err := scsidecar.NewListener(hostCfg, mgr)
	require.NoError(t, err)
	go func() { _ = lst.Serve() }()
	t.Cleanup(func() { _ = lst.Close(context.Background()) })

	reg := sidecar.Registration{Name: "sidescale.test", InstanceID: testInstanceID, Resume: true}
	conn, err := sidecar.Dial(t.Context(), socket, reg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	serverKey := key.NewNode()
	nodeKey := key.NewNode()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	router := sidecar.NewStreamRouter(conn)
	h := NewHandler(ctx, conn, router, cfg, "sidescale.test", serverKey,
		func(string) (key.NodePrivate, error) { return nodeKey, nil })

	// serve the router so bytes on dialed upstream streams reach their StreamConn
	go func() { _ = conn.Serve(ctx, router) }()
	return h
}
