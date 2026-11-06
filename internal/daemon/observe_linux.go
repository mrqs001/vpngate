//go:build linux

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/mrqs001/vpngate/internal/health"
)

const snapshotPeriod = 2 * time.Second
const kernelHealthPeriod = 10 * time.Second
const snapshotStaleAfter = 10 * time.Second
const kernelHealthStaleAfter = 30 * time.Second
const futureTimestampTolerance = time.Second

type Observation struct {
	SchemaVersion        int            `json:"schema_version"`
	Name                 string         `json:"name"`
	Running              bool           `json:"running"`
	Started              time.Time      `json:"started"`
	SupervisorPID        int            `json:"supervisor_pid"`
	WorkerPID            int            `json:"worker_pid"`
	WorkerStartTicks     string         `json:"worker_start_ticks"`
	SupervisorStartTicks string         `json:"supervisor_start_ticks"`
	SampledAt            time.Time      `json:"sampled_at"`
	RefreshSeconds       int            `json:"refresh_interval_seconds"`
	StaleAfterSeconds    int            `json:"stale_after_seconds"`
	KernelRefreshSeconds int            `json:"kernel_refresh_interval_seconds"`
	ConfiguredTunnels    int            `json:"configured_tunnels"`
	Proxy                map[string]any `json:"proxy"`
	Error                string         `json:"error,omitempty"`
	AgeSeconds           float64        `json:"age_seconds,omitempty"`
	Stale                bool           `json:"stale"`
}

type laneHealth struct {
	health.Link
	State               string   `json:"state"`
	Reason              string   `json:"reason"`
	SkipRecommended     bool     `json:"skip_recommended"`
	AgeSeconds          float64  `json:"age_seconds"`
	StaleAfterSeconds   int      `json:"stale_after_seconds"`
	HandshakeAgeSeconds *float64 `json:"handshake_age_seconds"`
	LastTrafficUnixMS   int64    `json:"last_download_activity_unix_ms"`
}

type observer struct {
	name             string
	state            State
	ids              []string
	probe            *health.Probe
	links            []health.Link
	samples          []downloadSample
	workerStartTicks string
	trafficAt        []int64
	nextKernel       time.Time
	routeHealth      bool
}

func (o *observer) collect(ctx context.Context, now time.Time) Observation {
	if !now.Before(o.nextKernel) {
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		o.links = o.probe.Sample(probeCtx)
		cancel()
		o.nextKernel = time.Now().Add(kernelHealthPeriod)
		if o.routeHealth {
			disabled := make([]bool, len(o.links))
			for i, link := range o.links {
				disabled[i] = assess(link, time.Now(), 0, 0, 0).SkipRecommended
			}
			_, _ = controlMessage(o.name, map[string]any{"op": "health", "disabled": disabled})
		}
	}
	out := Observation{SchemaVersion: 1, Name: o.name, Running: true, Started: o.state.Started,
		SupervisorPID: o.state.PID, WorkerPID: o.state.WorkerPID, SupervisorStartTicks: o.state.StartTicks,
		WorkerStartTicks: o.workerStartTicks,
		RefreshSeconds:   int(snapshotPeriod / time.Second), StaleAfterSeconds: int(snapshotStaleAfter / time.Second),
		KernelRefreshSeconds: int(kernelHealthPeriod / time.Second), ConfiguredTunnels: len(o.ids)}
	raw, err := Control(o.name, "status", 0)
	if err == nil {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		err = decoder.Decode(&out.Proxy)
	}
	observedAt := time.Now() // Keep monotonic time for rate intervals, UTC for JSON.
	out.SampledAt = observedAt.UTC()
	if err != nil {
		out.Running = false
		out.Error = "worker_status_unavailable"
		return out
	}
	lanes, ok := out.Proxy["lanes"].([]any)
	if !ok || len(lanes) != len(o.ids) {
		out.Proxy = nil
		out.Running = false
		out.Error = "worker_status_invalid"
		return out
	}
	for i, value := range lanes {
		lane, ok := value.(map[string]any)
		if !ok || lane["id"] != o.ids[i] {
			out.Proxy = nil
			out.Running = false
			out.Error = "worker_status_invalid"
			return out
		}
		current := number(lane["download_bytes"])
		if current > o.samples[i].bytes {
			o.trafficAt[i] = out.SampledAt.UnixMilli()
		}
		rate, interval := o.samples[i].observe(current, observedAt, o.state.WorkerPID, o.workerStartTicks)
		lane["download_rate_mbps"] = rate
		lane["rate_interval_seconds"] = interval
		lane["health"] = assess(o.links[i], out.SampledAt, int64(number(lane["last_success_unix_ms"])), int64(number(lane["last_failure_unix_ms"])), o.trafficAt[i])
	}
	return out
}

// Rates are calculated only when collecting status; forwarding does no extra
// work. A counter decrease or worker change starts a new measurement window.
type downloadSample struct {
	bytes            uint64
	at               time.Time
	workerPID        int
	workerStartTicks string
}

func (s *downloadSample) observe(bytes uint64, at time.Time, pid int, start string) (*float64, *float64) {
	old := *s
	*s = downloadSample{bytes: bytes, at: at, workerPID: pid, workerStartTicks: start}
	seconds := at.Sub(old.at).Seconds()
	if old.at.IsZero() || seconds <= 0 || bytes < old.bytes || old.workerPID != pid || old.workerStartTicks != start {
		return nil, nil
	}
	rate := float64(bytes-old.bytes) / seconds / 1e6
	return &rate, &seconds
}
func number(v any) uint64 {
	if n, ok := v.(json.Number); ok {
		value, _ := strconv.ParseUint(string(n), 10, 64)
		return value
	}
	return 0
}

func assess(link health.Link, now time.Time, success, failure, traffic int64) laneHealth {
	age := now.Sub(link.SampledAt).Seconds()
	out := laneHealth{Link: link, State: "unknown", Reason: "probe_unavailable", AgeSeconds: age,
		StaleAfterSeconds: int(kernelHealthStaleAfter / time.Second), LastTrafficUnixMS: traffic}
	if link.WireGuard != nil && link.WireGuard.LatestHandshakeUnix > 0 {
		seconds := float64(now.Unix() - link.WireGuard.LatestHandshakeUnix)
		if seconds >= 0 {
			out.HandshakeAgeSeconds = &seconds
		}
	}
	if link.SampledAt.IsZero() || age < -futureTimestampTolerance.Seconds() || age > kernelHealthStaleAfter.Seconds() {
		out.Reason = "stale_kernel_sample"
		return out
	}
	down := ""
	switch {
	case link.NamespaceState == "missing":
		down = "namespace_missing"
	case link.NamespaceState == "replaced":
		down = "namespace_replaced"
	case link.Error == "interface_missing":
		down = "interface_missing"
	case link.InterfaceUp != nil && !*link.InterfaceUp:
		down = "interface_down"
	case link.WireGuard != nil && link.WireGuard.Peers == 0:
		down = "no_wireguard_peers"
	}
	if down != "" {
		out.State = "down"
		out.Reason = down
		out.SkipRecommended = true
		return out
	}
	if link.NamespaceState != "present" {
		return out
	}
	latestSuccess := max(success, traffic)
	nowMS := now.UnixMilli()
	if failure > latestSuccess && failure <= nowMS && nowMS-failure < 60_000 {
		out.State = "degraded"
		out.Reason = "recent_proxy_failures"
		return out
	}
	if latestSuccess > 0 && latestSuccess <= nowMS && nowMS-latestSuccess < 60_000 {
		out.State = "up"
		out.Reason = "recent_proxy_success"
		return out
	}
	if link.Error != "" {
		out.Reason = link.Error
		return out
	}
	if link.InterfaceUp != nil && *link.InterfaceUp {
		if out.HandshakeAgeSeconds != nil && *out.HandshakeAgeSeconds < 180 {
			out.State = "up"
			out.Reason = "recent_wireguard_handshake"
		} else {
			out.State = "idle"
			out.Reason = "no_recent_activity"
		}
	}
	return out
}

// Publishing is opt-in. Only counters and sanitized health cross this read-only
// boundary. The control socket and ownership journal keep their private modes.
func startObserver(ctx context.Context, name string, state State, ids, names, interfaces []string, public, routeHealth bool) (func(), error) {
	probe, err := health.New(names, interfaces)
	if err != nil {
		return nil, err
	}
	for _, dir := range []string{"/run/vpngate", RuntimeDir(name)} {
		// Run has already validated root ownership, directory type and write modes.
		if err = os.Chmod(dir, 0755); err != nil {
			return nil, err
		}
	}
	workerStart, err := procStart(state.WorkerPID)
	if err != nil {
		return nil, errors.New("cannot identify status worker")
	}
	o := &observer{name: name, state: state, ids: ids, probe: probe, samples: make([]downloadSample, len(ids)), workerStartTicks: workerStart, trafficAt: make([]int64, len(ids)), routeHealth: routeHealth}
	child, cancel := context.WithCancel(ctx)
	file := filepath.Join(RuntimeDir(name), "status.json")
	initial := o.collect(child, time.Now())
	if public {
		err = publish(file, initial)
	}
	if err != nil {
		cancel()
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(snapshotPeriod)
		defer tick.Stop()
		for {
			select {
			case <-child.Done():
				return
			case <-tick.C:
				snapshot := o.collect(child, time.Now())
				if child.Err() != nil {
					return
				}
				if public && publish(file, snapshot) != nil {
					_ = os.Remove(file)
				}
			}
		}
	}()
	return func() { cancel(); <-done; _ = os.Remove(file); _ = os.Remove(file + ".tmp") }, nil
}

func publish(path string, snapshot Observation) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	// This is a disposable read-only snapshot, never the ownership journal.
	if err = os.Remove(temporary); err != nil && !os.IsNotExist(err) {
		return err
	}
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	_, err = file.Write(append(data, '\n'))
	if err == nil {
		err = file.Chmod(0644)
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// PublicStatus recalculates freshness and process identity instead of presenting
// a snapshot left by a crashed process as healthy. File readers must likewise
// check sampled_at/stale_after_seconds and discard stale health recommendations.
func PublicStatus(name string) (Observation, error) {
	return readPublicStatus(filepath.Join(RuntimeDir(name), "status.json"), time.Now())
}

func readPublicStatus(path string, now time.Time) (Observation, error) {
	var out Observation
	data, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err = decoder.Decode(&out); err != nil {
		return out, errors.New("invalid status snapshot")
	}
	out.AgeSeconds = now.Sub(out.SampledAt).Seconds()
	start, err := procStart(out.SupervisorPID)
	out.Stale = out.AgeSeconds < -futureTimestampTolerance.Seconds() || out.AgeSeconds > snapshotStaleAfter.Seconds() || err != nil || start != out.SupervisorStartTicks
	if out.Stale {
		out.Running = false
		if lanes, ok := out.Proxy["lanes"].([]any); ok {
			for _, value := range lanes {
				if lane, ok := value.(map[string]any); ok {
					if health, ok := lane["health"].(map[string]any); ok {
						health["state"] = "unknown"
						health["reason"] = "stale_snapshot"
						health["skip_recommended"] = false
					}
				}
			}
		}
	}
	return out, nil
}
