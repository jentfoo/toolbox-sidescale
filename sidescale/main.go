// Command sidescale is the Tailscale control-channel + DERP MITM sidecar: it
// registers with sectool as a protocol adapter and mediates the ts2021/DERP surfaces.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-appsec/toolbox/sectool/config"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/jentfoo/toolbox-sidescale/sidescale/derp"
	"github.com/jentfoo/toolbox-sidescale/sidescale/noise"
)

// setupTimeout bounds the startup /key fetch and responder registration.
const setupTimeout = 30 * time.Second

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

	conn, err := sidecar.Dial(ctx, socket, buildRegistration(cfg, instanceID))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.Log("info", "sidescale registered", map[string]any{
		"name":          cfg.Name,
		"socket":        socket,
		"control_hosts": cfg.Control.ControlHosts,
		"derp":          cfg.Derp != nil,
	})

	// one shared router serves both surfaces: claimed streams via Accept, dialed upstreams via DialUpstream
	router := sidecar.NewStreamRouter(conn)

	nh := noise.NewHandler(ctx, conn, router, cfg.Control, cfg.Name, responderKey, machineKey)
	nh.SetBindingKeys(regSigner, hwSigner)
	setupCtx, cancelSetup := context.WithTimeout(ctx, setupTimeout)
	err = nh.Setup(setupCtx)
	cancelSetup()
	if err != nil {
		return err
	}
	defer nh.Close(context.Background())

	var dh *derp.Handler
	if cfg.Derp != nil {
		serverKey, err := derp.ProvisionServerNodeKey(cfg.Derp)
		if err != nil {
			return err
		}
		nodeKey, err := derp.NewNodeKeyProvider(cfg.Derp)
		if err != nil {
			return err
		}
		dh = derp.NewHandler(ctx, conn, router, cfg.Derp, cfg.Name, serverKey, nodeKey)
	}
	d := newDispatcher(conn, router, cfg, nh, dh)
	go d.acceptLoop(ctx)

	serveErr := conn.Serve(ctx, d)
	_ = conn.Log("info", "sidescale stopped", nil)
	if serveErr != nil && !errors.Is(serveErr, context.Canceled) {
		return serveErr
	}
	return nil
}
