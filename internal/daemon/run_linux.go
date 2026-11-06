//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mrqs001/vpngate/internal/config"
	"github.com/mrqs001/vpngate/internal/netns"
	"github.com/mrqs001/vpngate/internal/proxy"
	"golang.org/x/sys/unix"
)

type State struct {
	PID        int        `json:"pid"`
	WorkerPID  int        `json:"worker_pid,omitempty"`
	StartTicks string     `json:"start_ticks"`
	Started    time.Time  `json:"started"`
	Resources  []Resource `json:"resources"`
}

func RuntimeDir(name string) string { return filepath.Join("/run/vpngate", name) }
func procStart(pid int) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	i := strings.LastIndex(string(b), ") ")
	if i < 0 {
		return "", errors.New("invalid process state")
	}
	fields := strings.Fields(string(b[i+2:]))
	if len(fields) < 20 {
		return "", errors.New("invalid process state")
	}
	return fields[19], nil
}

func safeDir(path string) error {
	if err := os.Mkdir(path, 0755); err != nil && !os.IsExist(err) {
		return err
	}
	s, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.IsDir() || st.Uid != 0 || s.Mode().Perm()&0022 != 0 {
		return errors.New("runtime directory must be root-owned and not writable by other users")
	}
	return nil
}

func Run(ctx context.Context, p Plan) (result error) {
	if os.Geteuid() != 0 {
		return errors.New("run requires root for namespace setup; use sudo")
	}
	u, err := user.Lookup(p.Config.RunAs)
	if err != nil {
		return errors.New("run_as user does not exist")
	}
	uid, e1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, e2 := strconv.ParseUint(u.Gid, 10, 32)
	if e1 != nil || e2 != nil || uid == 0 {
		return errors.New("run_as must identify an unprivileged user")
	}
	runtimeCfg, err := p.Config.Runtime()
	if err != nil {
		return err
	}
	if err = safeDir("/run/vpngate"); err != nil {
		return err
	}
	dir := RuntimeDir(p.Config.Name)
	if err = safeDir(dir); err != nil {
		return err
	}
	lockFD, err := unix.Open(filepath.Join(dir, "lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(lockFD)
	if unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errors.New("this gateway instance is already running")
	}
	defer unix.Flock(lockFD, unix.LOCK_UN)
	statePath := filepath.Join(dir, "state.json")
	if _, err = os.Lstat(statePath); err == nil {
		return errors.New("previous state exists; inspect status and use cleanup after an unclean shutdown")
	}
	// Reserve endpoints before touching any tunnel.
	var listeners []*os.File
	defer func() {
		for _, f := range listeners {
			if f != nil {
				f.Close()
			}
		}
	}()
	addresses := make([]string, len(p.Config.Tunnels))
	for i, t := range p.Config.Tunnels {
		addresses[i] = t.Listen
	}
	if p.Config.Fetch != nil {
		addresses = append(addresses, p.Config.Fetch.Listen)
	}
	for _, address := range addresses {
		if address == "" {
			listeners = append(listeners, nil)
			continue
		}
		l, e := net.Listen(config.ListenNetwork(address), address)
		if e != nil {
			return errors.New("listen endpoint unavailable")
		}
		f, e := l.(*net.TCPListener).File()
		l.Close()
		if e != nil {
			return e
		}
		listeners = append(listeners, f)
	}
	controlPath := filepath.Join(dir, "control.sock")
	if err = os.Remove(controlPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	control, err := net.ListenUnix("unix", &net.UnixAddr{Name: controlPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer control.Close()
	defer os.Remove(controlPath)
	if err = os.Chmod(controlPath, 0600); err != nil {
		return err
	}
	controlFile, err := control.File()
	if err != nil {
		return err
	}
	defer controlFile.Close()
	// The bound exceeds frontend sockets, pooled upstreams, listeners and transient DNS.
	var limit unix.Rlimit
	if err = unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return err
	}
	// CONNECT uses two sockets and one download pipe (two more FDs).
	need := uint64(4*p.Config.MaxConnections + len(p.Resources)*12 + 128)
	if limit.Cur < need {
		limit.Cur = need
		if limit.Max < need {
			limit.Max = need
		}
		if err = unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
			return errors.New("cannot raise descriptor limit")
		}
	}
	start, err := procStart(os.Getpid())
	if err != nil {
		return err
	}
	state := State{PID: os.Getpid(), StartTicks: start, Started: time.Now().UTC()}
	for _, r := range p.Resources {
		if !r.Owned {
			state.Resources = append(state.Resources, r)
		}
	}
	writeState := func() error {
		b, e := json.MarshalIndent(state, "", "  ")
		if e != nil {
			return e
		}
		tmp := statePath + ".tmp"
		f, e := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if e != nil {
			return e
		}
		_, e = f.Write(b)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e == nil {
			e = closeErr
		}
		if e != nil {
			os.Remove(tmp)
			return e
		}
		return os.Rename(tmp, statePath)
	}
	if err = writeState(); err != nil {
		return err
	}
	cleanup, err := p.setup(ctx, Commands{}, func(r Resource) error {
		for i, old := range state.Resources {
			if old.ID == r.ID {
				state.Resources[i] = r
				return writeState()
			}
		}
		state.Resources = append(state.Resources, r)
		return writeState()
	})
	if err != nil {
		// A failed setup keeps its ownership journal for explicit recovery.
		return err
	}
	// Keep state when cleanup fails so explicit recovery remains possible.
	defer func() {
		if err := cleanup(); err == nil {
			os.Remove(statePath)
		} else {
			result = errors.Join(result, errors.New("owned tunnel cleanup incomplete; inspect status and run cleanup"))
		}
	}()
	names := make([]string, len(p.Resources))
	interfaces := make([]string, len(p.Resources))
	for i, r := range p.Resources {
		names[i] = r.Namespace
		interfaces[i] = p.Config.Tunnels[i].Interface
		if r.Owned {
			interfaces[i] = r.Device
		}
	}
	factory, closeFactory, err := netns.NamespaceFactory(names, interfaces)
	if err != nil {
		return err
	}
	defer closeFactory()
	parent, child, err := netns.SocketPair()
	if err != nil {
		return err
	}
	defer parent.Close()
	defer child.Close()
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err := os.Open(exe)
	if err != nil {
		return err
	}
	defer executable.Close()
	// Execute an inherited descriptor so the worker can run even when the user's
	// development checkout is inside a private home directory.
	cmd := exec.Command("/proc/self/fd/5", "__serve")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}, Pdeathsig: syscall.SIGTERM}
	cmd.ExtraFiles = append([]*os.File{child, controlFile, executable}, listeners...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Do not pass provider/proxy credentials from the supervisor's environment.
	cmd.Env = []string{"GOMAXPROCS=" + strconv.Itoa(p.Config.WorkerThreads)}
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	// Linux's parent-death signal tracks the creating OS thread. Keep it alive for
	// the child's lifetime rather than allowing Go to retire/reuse it.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err = cmd.Start(); err != nil {
		return errors.New("cannot start unprivileged proxy process")
	}
	child.Close()
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	brokerDone := make(chan error, 1)
	go func() { brokerDone <- netns.ServeBroker(parent, factory) }()
	if err = json.NewEncoder(in).Encode(runtimeCfg); err != nil {
		in.Close()
		cmd.Process.Kill()
		<-wait
		parent.Close()
		<-brokerDone
		return errors.New("cannot initialize proxy process")
	}
	in.Close()
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if _, e := Control(p.Config.Name, "status", 0); e == nil {
			ready = true
			break
		}
		select {
		case <-wait:
			parent.Close()
			<-brokerDone
			return errors.New("proxy worker failed during startup")
		case <-ctx.Done():
			cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-wait:
			case <-time.After(5 * time.Second):
				cmd.Process.Kill()
				<-wait
			}
			parent.Close()
			<-brokerDone
			return nil
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !ready {
		cmd.Process.Kill()
		<-wait
		parent.Close()
		<-brokerDone
		return errors.New("proxy worker readiness timeout")
	}
	state.WorkerPID = cmd.Process.Pid
	err = writeState()
	if err == nil && (p.Config.PublicStatus || p.Config.Fetch != nil) {
		ids := make([]string, len(p.Resources))
		for i, r := range p.Resources {
			ids[i] = r.ID
		}
		var stopObserver func()
		stopObserver, err = startObserver(ctx, p.Config.Name, state, ids, names, interfaces, p.Config.PublicStatus, p.Config.Fetch != nil)
		if stopObserver != nil {
			defer stopObserver()
		}
	}
	if err == nil {
		err = notifyReady()
	}
	if err != nil {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-wait:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-wait
		}
		parent.Close()
		<-brokerDone
		return err
	}
	fmt.Printf("vpngate %s: %d tunnels ready; supervisor %d\n", p.Config.Name, len(p.Resources), os.Getpid())
	select {
	case err = <-wait:
		parent.Close()
		<-brokerDone
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("proxy process exited unexpectedly")
	case <-brokerDone:
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-wait:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-wait
		}
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("socket broker stopped")
	case <-ctx.Done():
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-wait:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-wait
		}
		parent.Close()
		<-brokerDone
		return nil
	}
}

// systemd waits for the worker/control endpoint, rather than treating a bound
// listener as readiness while managed tunnels are still being configured.
func notifyReady() error {
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" {
		return nil
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
	if err != nil {
		return errors.New("cannot notify service manager of readiness")
	}
	defer c.Close()
	c.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = c.Write([]byte("READY=1"))
	if err != nil {
		return errors.New("cannot notify service manager of readiness")
	}
	return nil
}

func ServeChild() error {
	if os.Geteuid() == 0 {
		return errors.New("proxy worker must run unprivileged")
	}
	// Locks out gaining privilege by exec even if an unexpected child were added later.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	var c config.Runtime
	d := json.NewDecoder(io.LimitReader(os.Stdin, 2<<20))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || len(c.Tunnels) == 0 || len(c.Tunnels) > 500 || c.MaxConnections < 1 || c.PerTunnel < 1 {
		return errors.New("invalid worker configuration")
	}
	f := os.NewFile(3, "broker")
	broker, err := netns.NewBroker(f)
	f.Close()
	if err != nil {
		return err
	}
	defer broker.Close()
	cf := os.NewFile(4, "control")
	control, err := net.FileListener(cf)
	cf.Close()
	if err != nil {
		return err
	}
	defer control.Close()
	os.NewFile(5, "worker-executable").Close()
	var listeners []net.Listener
	listenerCount := len(c.Tunnels)
	if c.Fetch != nil {
		listenerCount++
	}
	for i := 0; i < listenerCount; i++ {
		if c.Fetch != nil && i < len(c.Tunnels) && c.Tunnels[i].Listen == "" {
			listeners = append(listeners, nil)
			continue
		}
		f := os.NewFile(uintptr(6+i), "proxy-listener")
		l, e := net.FileListener(f)
		f.Close()
		if e != nil {
			for _, v := range listeners {
				if v != nil {
					v.Close()
				}
			}
			return errors.New("invalid listener descriptor")
		}
		listeners = append(listeners, l)
	}
	g := proxy.New(c, broker)
	if err = g.Start(listeners); err != nil {
		return err
	}
	defer g.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	controlDone := make(chan error, 1)
	go func() { controlDone <- g.Control(control) }()
	select {
	case <-ctx.Done():
		control.Close()
		<-controlDone
		return nil
	case <-controlDone:
		return errors.New("control listener stopped")
	case <-g.Errors():
		control.Close()
		<-controlDone
		return errors.New("proxy listener stopped")
	}
}

func Control(name, op string, mbps float64) (json.RawMessage, error) {
	return controlMessage(name, map[string]any{"op": op, "mbps": mbps})
}

func controlMessage(name string, message any) (json.RawMessage, error) {
	c, err := net.DialTimeout("unix", filepath.Join(RuntimeDir(name), "control.sock"), time.Second)
	if err != nil {
		return nil, errors.New("gateway control unavailable (run control commands with sudo)")
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if err = json.NewEncoder(c).Encode(message); err != nil {
		return nil, err
	}
	var result json.RawMessage
	err = json.NewDecoder(io.LimitReader(c, 2<<20)).Decode(&result)
	return result, err
}

func Status(name string) (State, bool, error) {
	var s State
	b, err := os.ReadFile(filepath.Join(RuntimeDir(name), "state.json"))
	if err != nil {
		return s, false, errors.New("instance has no recorded state")
	}
	if json.Unmarshal(b, &s) != nil {
		return s, false, errors.New("invalid state file")
	}
	start, err := procStart(s.PID)
	return s, err == nil && start == s.StartTicks, nil
}

func Stop(name string) error {
	s, alive, err := Status(name)
	if err != nil {
		return err
	}
	if !alive {
		return errors.New("recorded supervisor is not running; use cleanup")
	}
	// pidfd prevents signaling a different process if the recorded PID exits/recycles.
	fd, err := unix.PidfdOpen(s.PID, 0)
	if err != nil {
		return errors.New("cannot open supervisor pidfd")
	}
	defer unix.Close(fd)
	start, err := procStart(s.PID)
	if err != nil || start != s.StartTicks {
		return errors.New("supervisor identity changed")
	}
	if unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0) != nil {
		return errors.New("cannot stop supervisor (use sudo)")
	}
	return nil
}

func Cleanup(name string) error {
	if os.Geteuid() != 0 {
		return errors.New("cleanup requires root")
	}
	dir := RuntimeDir(name)
	fd, err := unix.Open(filepath.Join(dir, "lock"), unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if os.IsNotExist(err) {
			if _, e := os.Lstat(filepath.Join(dir, "state.json")); os.IsNotExist(e) {
				return nil
			}
		}
		return err
	}
	defer unix.Close(fd)
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errors.New("instance is running; cleanup refused")
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	s, alive, err := Status(name)
	if err != nil {
		if _, e := os.Lstat(filepath.Join(dir, "state.json")); os.IsNotExist(e) {
			os.Remove(filepath.Join(dir, "status.json"))
			os.Remove(filepath.Join(dir, "status.json.tmp"))
			return nil
		}
		return err
	}
	if alive {
		return errors.New("supervisor still exists; cleanup refused")
	}
	for _, r := range s.Resources {
		if !r.Owned {
			continue
		}
		ns, dev := Names(name, r.ID)
		if r.Namespace != ns || r.Device != dev {
			return errors.New("state contains a resource outside this instance")
		}
		if r.HostDevice {
			if _, e := net.InterfaceByName(dev); e == nil {
				if err = (Commands{}).Run(context.Background(), "/usr/bin/ip", []string{"link", "delete", dev}, ""); err != nil {
					return err
				}
			}
		}
		// A broker/frontend from an unclean shutdown must be gone before deleting its namespace.
		// The child is coupled to the supervisor through PR_SET_PDEATHSIG.
		if _, e := os.Stat("/var/run/netns/" + ns); os.IsNotExist(e) {
			continue
		}
		if err = (Commands{}).Run(context.Background(), "/usr/bin/ip", []string{"netns", "delete", ns}, ""); err != nil {
			return err
		}
	}
	os.Remove(filepath.Join(dir, "control.sock"))
	os.Remove(filepath.Join(dir, "status.json"))
	os.Remove(filepath.Join(dir, "status.json.tmp"))
	return os.Remove(filepath.Join(dir, "state.json"))
}
