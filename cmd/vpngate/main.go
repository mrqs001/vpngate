package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"runtime/pprof"
	"syscall"

	"github.com/mrqs001/vpngate/internal/config"
	"github.com/mrqs001/vpngate/internal/daemon"
	"github.com/mrqs001/vpngate/internal/embedded"
	_ "golang.org/x/crypto/x509roots/fallback" // HTTPS also works without a system CA bundle.
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "vpngate:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Println("vpngate — standalone WireGuard to HTTP proxy gateway\n\nCommands:\n  check --config FILE       validate configuration without network changes\n  run --config FILE         start in foreground (embedded: no sudo); Ctrl-C stops\n  status --name NAME         show kernel-mode status\n  limit --name NAME --mbps N change kernel-mode download cap (0 = unlimited)\n  stop --name NAME           stop and clean up owned kernel resources\n  cleanup --name NAME        recover recorded kernel resources after abnormal exit\n  version                   print version\n\nEmbedded prototype: inline wireguard settings; one fetch listener; no VPN tools.\n  run --config FILE --cpu-profile FILE  record a local CPU profile")
		return nil
	}
	if len(args) > 0 && args[0] == "version" {
		fmt.Println("vpngate 0.5.0-embedded-prototype")
		return nil
	}
	if len(args) == 0 {
		return errors.New("usage: vpngate check|run|status|stop|limit|cleanup [options]")
	}
	if args[0] == "__serve" {
		return daemon.ServeChild()
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	path := f.String("config", "vpngate.json", "explicit gateway JSON configuration")
	name := f.String("name", "default", "gateway instance name")
	rate := f.Float64("mbps", 0, "aggregate download MB/s; 0 = unlimited")
	profile := f.String("cpu-profile", "", "write CPU profile (embedded run only)")
	if err := f.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	if *profile != "" && args[0] != "run" {
		return errors.New("cpu-profile is only valid with run")
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`).MatchString(*name) {
		return errors.New("invalid instance name")
	}
	switch args[0] {
	case "check", "run":
		c, err := config.Load(*path)
		if err != nil {
			return err
		}
		nameGiven := false
		f.Visit(func(v *flag.Flag) {
			if v.Name == "name" {
				nameGiven = true
			}
		})
		if nameGiven && c.Name != *name {
			return errors.New("instance name does not match configuration")
		}
		if c.Embedded() {
			if _, err := c.Runtime(); err != nil {
				return err
			}
			if args[0] == "check" {
				fmt.Printf("valid: %s, %d embedded tunnels; no network changes\n", c.Name, len(c.Tunnels))
				return nil
			}
			if *profile != "" {
				file, err := os.OpenFile(*profile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if err != nil {
					return errors.New("cannot create CPU profile")
				}
				defer file.Close()
				if err := pprof.StartCPUProfile(file); err != nil {
					return err
				}
				defer pprof.StopCPUProfile()
			}
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			return embedded.Run(ctx, c)
		}
		if *profile != "" {
			return errors.New("cpu-profile requires embedded mode")
		}
		p, err := daemon.Prepare(c)
		if err != nil {
			return err
		}
		if _, err = p.Config.Runtime(); err != nil {
			return err
		}
		if args[0] == "check" {
			fmt.Printf("valid: %s, %d tunnels; no network changes\n", c.Name, len(c.Tunnels))
			return nil
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return daemon.Run(ctx, p)
	case "status":
		if snapshot, e := daemon.PublicStatus(*name); e == nil {
			return json.NewEncoder(os.Stdout).Encode(snapshot)
		}
		s, alive, err := daemon.Status(*name)
		if err != nil {
			return err
		}
		out := map[string]any{"name": *name, "running": alive, "started": s.Started, "configured_tunnels": len(s.Resources), "supervisor_pid": s.PID, "worker_pid": s.WorkerPID}
		if alive {
			if data, e := daemon.Control(*name, "status", 0); e == nil {
				out["proxy"] = data
			}
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	case "stop":
		return daemon.Stop(*name)
	case "cleanup":
		return daemon.Cleanup(*name)
	case "limit":
		found := false
		f.Visit(func(v *flag.Flag) {
			if v.Name == "mbps" {
				found = true
			}
		})
		if !found || !config.ValidRate(*rate) {
			return errors.New("limit requires --mbps (0 means unlimited)")
		}
		data, err := daemon.Control(*name, "limit", *rate)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	default:
		return errors.New("unknown command")
	}
}
