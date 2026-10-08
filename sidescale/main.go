// Command sidescale is the Tailscale control-channel + DERP MITM sidecar: it
// registers with sectool as a protocol adapter and mediates the ts2021/DERP surfaces.
package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"syscall"
	"time"

	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/sectool/config"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/jentfoo/toolbox-sidescale/sidescale/derp"
	"github.com/jentfoo/toolbox-sidescale/sidescale/noise"
	"github.com/jentfoo/toolbox-sidescale/sidescale/noise/bindings"
)

// setupTimeout bounds the startup /key fetch and responder registration.
const setupTimeout = 30 * time.Second

// Reconnect pacing. Vars so tests can shorten them.
var (
	reconnectInitial = time.Second
	reconnectMax     = 30 * time.Second
	// reconnectStable is the served duration after which a session counts as healthy,
	// resetting the backoff escalation and the outage window.
	reconnectStable = 10 * time.Second
	// reconnectWindow bounds how long the process keeps retrying a dead host before
	// exiting nonzero so a supervisor can intervene.
	reconnectWindow = 5 * time.Minute
)

// errRemoteDrop marks a Serve return caused by the peer disappearing, not a signal.
var errRemoteDrop = errors.New("transport closed")

// errSessionSetup marks a /key substitution setup failure: transient on a reconnect
// (the host may still be settling), fatal on first start.
var errSessionSetup = errors.New("session setup failed")

// keyMaterial bundles the once-per-process key material shared by every reconnect
// session, so an ephemeral client-facing key stays stable across sectool restarts.
type keyMaterial struct {
	responder key.MachinePrivate // client-facing Noise responder key
	machine   func(client string) (key.MachinePrivate, error)
	regSigner *bindings.RegisterSigner // register rebind signer, nil when unconfigured
	hwSigner  *ecdsa.PrivateKey        // hardware attestation signer, nil when unconfigured
	derpSrv   key.NodePrivate          // client-facing DERP server key
	derpNode  func(client string) (key.NodePrivate, error)
}

func main() {
	var configPath, socketOverride string
	flag.StringVar(&configPath, "config", "", "sidescale config file path")
	flag.StringVar(&socketOverride, "sidecar-socket", "", "sectool sidecar IPC socket (overrides config)")
	flag.Parse()

	if err := run(configPath, socketOverride); err != nil {
		log.Fatalf("sidescale: %v", err)
	}
}

func run(configPath, socketOverride string) error {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	responderKey, err := noise.ProvisionResponderKey(cfg.Control)
	if err != nil {
		return err
	}
	machineKey, err := noise.NewMachineKeyProvider(cfg.Control)
	if err != nil {
		return err
	}
	regSigner, hwSigner, err := noise.LoadBindingKeys(cfg.Control)
	if err != nil {
		return err
	}
	km := keyMaterial{responder: responderKey, machine: machineKey, regSigner: regSigner, hwSigner: hwSigner}
	if cfg.Derp != nil {
		if km.derpSrv, err = derp.ProvisionServerNodeKey(cfg.Derp); err != nil {
			return err
		}
		if km.derpNode, err = derp.NewNodeKeyProvider(cfg.Derp); err != nil {
			return err
		}
	}
	instanceID, err := stableInstanceID(cfg.Name)
	if err != nil {
		return err
	}
	socket := socketOverride // prefer override, then config, then default
	if socket == "" {
		socket = cfg.Sectool.Socket
	}
	if socket == "" {
		socket = config.DefaultSidecarSocket()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return serveForever(ctx, cfg, socket, km, instanceID)
}

// serveForever dials sectool and serves sessions until the signal context fires,
// reconnecting with backoff when the transport drops. A failed first dial is fatal
// (bad socket, host never up). Once a session has served, retries continue until
// reconnectWindow elapses without a healthy session, then the returned error makes
// the process exit nonzero so a supervisor can intervene.
func serveForever(ctx context.Context, cfg Config, socket string, km keyMaterial, instanceID string) error {
	reg := buildRegistration(cfg, instanceID)
	backoff := reconnectInitial
	var outage time.Time // start of the current outage window; zero while healthy

	// reconnectWait paces one failed attempt. retry=false means stop: fatal is nil
	// for a signal exit, set once the outage window has elapsed.
	reconnectWait := func(cause error) (retry bool, fatal error) {
		if outage.IsZero() {
			outage = time.Now()
		}
		if time.Since(outage) > reconnectWindow {
			return false, fmt.Errorf("sidescale: no healthy sectool session for over %s: %w", reconnectWindow, cause)
		}
		log.Printf("sidescale: reconnect: %v (next attempt in %s)", cause, backoff)
		if !sleepBackoff(ctx, backoff) {
			return false, nil
		}
		backoff = min(backoff*2, reconnectMax)
		return true, nil
	}

	for attempt := 0; ; attempt++ {
		conn, err := sidecar.Dial(ctx, socket, reg)
		if err != nil {
			if ctx.Err() != nil {
				log.Println("sidescale stopped") // stderr: survives the dead peer
				return nil
			}
			if attempt == 0 {
				return fmt.Errorf("sidescale: dial sectool at %s: %w", socket, err)
			}
			if retry, fatal := reconnectWait(fmt.Errorf("dial %s: %w", socket, err)); !retry {
				return fatal
			}
			continue
		}

		served, err := serveSession(ctx, conn, cfg, socket, km)
		if ctx.Err() != nil {
			log.Println("sidescale stopped") // stderr: survives the dead peer
			return nil
		}
		if err != nil {
			if attempt > 0 && errors.Is(err, errSessionSetup) {
				// setup failing on a reconnect is the outage continuing, not a new problem
				if retry, fatal := reconnectWait(err); !retry {
					return fatal
				}
				continue
			}
			return err
		}

		// Serve returned with a live signal context and no error: the transport dropped.
		if served >= reconnectStable {
			backoff, outage = reconnectInitial, time.Time{} // healthy session: reset escalation
		}
		if retry, fatal := reconnectWait(fmt.Errorf("%w after %s", errRemoteDrop, served.Round(time.Second))); !retry {
			return fatal
		}
	}
}

// sleepBackoff waits d or until the signal context fires; false means the signal won.
func sleepBackoff(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// serveSession runs one registered session: wires the surfaces, runs setup, and serves
// until the signal context fires or the peer drops. It returns how long the session
// served and closes the conn before returning.
func serveSession(ctx context.Context, conn *sidecar.Conn, cfg Config, socket string, km keyMaterial) (time.Duration, error) {
	defer func() { _ = conn.Close() }()

	sessionCtx, cancel := context.WithCancel(ctx) // bounds handler-spawned work for this conn
	defer cancel()

	_ = conn.Log("info", "sidescale registered", map[string]any{
		"name":          cfg.Name,
		"socket":        socket,
		"control_hosts": cfg.Control.ControlHosts,
		"derp":          cfg.Derp != nil,
	})

	// one shared router serves both surfaces: claimed streams via Accept, dialed upstreams via DialUpstream
	router := sidecar.NewStreamRouter(conn)

	nh := noise.NewHandler(sessionCtx, conn, router, cfg.Control, cfg.Name, km.responder, km.machine)
	nh.SetBindingKeys(km.regSigner, km.hwSigner)

	var dh *derp.Handler
	if cfg.Derp != nil {
		dh = derp.NewHandler(sessionCtx, conn, router, cfg.Derp, cfg.Name, km.derpSrv, km.derpNode)
	}
	d := newDispatcher(conn, router, cfg, nh, dh)
	// claims match traffic the moment Dial returns, so install the dispatcher and accept
	// streams before Setup's network work; tunnels hold on the surfaces' setup gate
	conn.SetHandler(d)
	go d.acceptLoop(sessionCtx)

	setupCtx, cancelSetup := context.WithTimeout(sessionCtx, setupTimeout)
	err := nh.Setup(setupCtx)
	cancelSetup()
	if err != nil {
		return 0, fmt.Errorf("%w: %w", errSessionSetup, err)
	}

	started := time.Now()
	serveErr := conn.Serve(sessionCtx, d)
	return time.Since(started), serveErr
}
