// Package sysroute owns the Windows network state mutations (roadmap Step 3):
// adapter addressing, the route overlay (0/0 via tunnel + ::/0 blackhole),
// and the DNS rewrite — all journaled through internal/failsafe so a crash
// cannot leave the host unreachable or leaking.
//
// Strategy: OVERLAY, NEVER DELETE. The tunnel default route simply wins on
// metric; physical routes stay intact for instant rollback. Kill-switch is
// fail-closed by construction: when the tunnel is down, traffic keeps
// entering Wintun and dies there — fail-open (falling back to the physical
// NIC) would leak raw Windows TTL=128 traffic, the exact fingerprint the
// system exists to prevent.
package sysroute

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/esdfurkan/toppa/desktop/internal/failsafe"
)

// InterfaceInfo is the minimal adapter identity the manager needs.
type InterfaceInfo struct {
	Name        string
	Description string
}

// NetConfigurer is the OS boundary. The netsh implementation shells out to
// Windows tooling (no extra dependencies, deterministic undo strings); a
// winipcfg/LUID implementation can replace it behind this interface.
type NetConfigurer interface {
	// SetInterfaceIP assigns ip/prefixLen to the adapter (undo restores DHCP).
	SetInterfaceIP(iface string, ip net.IP, prefixLen int) (undo []string, err error)
	// AddRoute adds an on-link route via iface (undo deletes it).
	AddRoute(dst *net.IPNet, iface string, metric int) (apply, undo []string, err error)
	// SetDNS sets the adapter's resolver list (undo resets to DHCP).
	SetDNS(iface string, servers []net.IP) (apply, undo []string, err error)
	// ListInterfaces enumerates adapters for the physical-DNS rewrite.
	ListInterfaces() ([]InterfaceInfo, error)
}

// NetshConfigurer shells out to netsh/route.
type NetshConfigurer struct{}

func run(cmd string, args ...string) error {
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysroute: %s %s: %w: %s", cmd, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (NetshConfigurer) SetInterfaceIP(iface string, ip net.IP, prefixLen int) (undo []string, err error) {
	// Wintun adapters are point-to-point style; a /32 fits any tunnel IP.
	apply := []string{"netsh", "interface", "ip", "set", "address", fmt.Sprintf("name=%q", iface), "source=static", "addr=" + ip.String(), "mask=255.255.255.255"}
	if err := run(apply[0], apply[1:]...); err != nil {
		return nil, err
	}
	return []string{"netsh", "interface", "ip", "set", "address", fmt.Sprintf("name=%q", iface), "source=dhcp"}, nil
}

func (NetshConfigurer) AddRoute(dst *net.IPNet, iface string, metric int) (apply, undo []string, err error) {
	mask := net.IP(dst.Mask).String()
	dstStr := dst.IP.String()
	gw := dst.IP.String() // on-link: the tunnel interface's own address
	apply = []string{"route", "add", dstStr, "mask", mask, gw, "metric", fmt.Sprint(metric), "if", iface}
	undoCmd := []string{"route", "delete", dstStr}
	if err := run(apply[0], apply[1:]...); err != nil {
		return nil, nil, err
	}
	return apply, undoCmd, nil
}

func (NetshConfigurer) SetDNS(iface string, servers []net.IP) (apply, undo []string, err error) {
	for i, s := range servers {
		var cmd []string
		if i == 0 {
			cmd = []string{"netsh", "interface", "ip", "set", "dns", fmt.Sprintf("name=%q", iface), "static", s.String(), "primary"}
		} else {
			cmd = []string{"netsh", "interface", "ip", "add", "dns", fmt.Sprintf("name=%q", iface), s.String(), "index=" + fmt.Sprint(i+1)}
		}
		if err := run(cmd[0], cmd[1:]...); err != nil {
			return apply, []string{"netsh", "interface", "ip", "set", "dns", fmt.Sprintf("name=%q", iface), "source=dhcp"}, err
		}
		apply = append(apply, strings.Join(cmd, " "))
	}
	return apply, []string{"netsh", "interface", "ip", "set", "dns", fmt.Sprintf("name=%q", iface), "source=dhcp"}, nil
}

func (NetshConfigurer) ListInterfaces() ([]InterfaceInfo, error) {
	out, err := exec.Command("netsh", "interface", "ipv4", "show", "interfaces").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sysroute: list interfaces: %w", err)
	}
	var ifaces []InterfaceInfo
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		// Header lines and the dashes separator are skipped; data rows look
		// like: <state> <idx> <metric> <mtu> <name...>
		if len(fields) < 5 {
			continue
		}
		if fields[0] != "connected" && fields[0] != "disconnected" {
			continue
		}
		ifaces = append(ifaces, InterfaceInfo{Name: strings.Join(fields[4:], " ")})
	}
	return ifaces, nil
}

// Desired is the network state the manager enforces while the tunnel is up.
type Desired struct {
	AdapterName        string
	TunnelIP           net.IP
	TunnelPrefixLen    int
	DefaultRouteMetric int
	DNS                []net.IP
	RewritePhysicalDNS bool
}

// Manager applies Desired through a NetConfigurer with journal-before-apply
// semantics, and reconciles leftovers from previous runs at startup.
type Manager struct {
	configurer NetConfigurer
	journal    *failsafe.Journal
	runFn      func(cmd string, args ...string) error
}

func NewManager(configurer NetConfigurer, journal *failsafe.Journal) *Manager {
	return &Manager{configurer: configurer, journal: journal, runFn: run}
}

// SetRunner overrides the command executor (tests inject a recorder).
func (m *Manager) SetRunner(fn func(cmd string, args ...string) error) {
	m.runFn = fn
}

// Reconcile rolls back leftovers from a previous crashed run. Call before
// applying any new state.
func (m *Manager) Reconcile() (int, error) {
	return m.journal.RollbackAll(func(e failsafe.Entry) error {
		for _, cmd := range e.Undo {
			fields := strings.Fields(cmd)
			if len(fields) == 0 {
				continue
			}
			if err := m.runFn(fields[0], fields[1:]...); err != nil {
				return err
			}
		}
		return nil
	})
}

// Apply enforces d, journaling each mutation before executing it.
func (m *Manager) Apply(d Desired) error {
	if m.configurer == nil {
		return fmt.Errorf("sysroute: nil configurer")
	}

	// 1) Adapter address.
	if undo, err := m.configurer.SetInterfaceIP(d.AdapterName, d.TunnelIP, d.TunnelPrefixLen); err != nil {
		return fmt.Errorf("sysroute: set interface ip: %w", err)
	} else if _, err := m.journal.Add("interface address "+d.TunnelIP.String(), []string{"netsh set address"}, undo); err != nil {
		return err
	}

	// 2) Default routes: 0.0.0.0/0 wins on metric; ::/0 makes the tunnel the
	// v6 default too — netstack answers with unreachable, which is the
	// IPv6-leak blackhole (ipv6.blackhole=true semantics from the design).
	defaultNet := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	for _, dst := range []*net.IPNet{
		defaultNet,
		{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
	} {
		apply, undo, err := m.configurer.AddRoute(dst, d.AdapterName, d.DefaultRouteMetric)
		if err != nil {
			return fmt.Errorf("sysroute: add route %s: %w", dst.String(), err)
		}
		if _, err := m.journal.Add("route "+dst.String(), apply, undo); err != nil {
			return err
		}
	}

	// 3) Tunnel DNS + physical-adapter rewrite (kills Windows parallel-query
	// leaks deterministically instead of fighting Smart Multi-Homed Name
	// Resolution).
	if len(d.DNS) > 0 {
		apply, undo, err := m.configurer.SetDNS(d.AdapterName, d.DNS)
		if err != nil {
			return fmt.Errorf("sysroute: set tunnel dns: %w", err)
		}
		if _, err := m.journal.Add("tunnel dns", apply, undo); err != nil {
			return err
		}
	}
	if d.RewritePhysicalDNS {
		ifaces, err := m.configurer.ListInterfaces()
		if err != nil {
			return err
		}
		for _, iface := range ifaces {
			if iface.Name == d.AdapterName {
				continue
			}
			apply, undo, err := m.configurer.SetDNS(iface.Name, d.DNS)
			if err != nil {
				return fmt.Errorf("sysroute: rewrite dns on %q: %w", iface.Name, err)
			}
			if _, err := m.journal.Add("physical dns "+iface.Name, apply, undo); err != nil {
				return err
			}
		}
	}
	return nil
}

// Rollback reverts everything this manager (or a crashed predecessor) applied.
func (m *Manager) Rollback() (int, error) {
	return m.journal.RollbackAll(func(e failsafe.Entry) error {
		for _, cmd := range e.Undo {
			fields := strings.Fields(cmd)
			if len(fields) == 0 {
				continue
			}
			if err := m.runFn(fields[0], fields[1:]...); err != nil {
				return err
			}
		}
		return nil
	})
}
