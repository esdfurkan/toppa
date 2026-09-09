package sysroute

import (
	"net"
	"strings"
	"testing"

	"github.com/esdfurkan/toppa/desktop/internal/failsafe"
)

// fakeConfigurer records commands instead of running them.
type fakeConfigurer struct {
	ips      []string
	routes   []string
	dns      []string
	failOn   string // substring; when set, the matching mutation errors
	ifaces   []InterfaceInfo
}

func (f *fakeConfigurer) SetInterfaceIP(iface string, ip net.IP, prefixLen int) ([]string, error) {
	if strings.Contains(iface, f.failOn) {
		return nil, errFake
	}
	f.ips = append(f.ips, ip.String())
	return []string{"undo ip " + ip.String()}, nil
}

func (f *fakeConfigurer) AddRoute(dst *net.IPNet, iface string, metric int) ([]string, []string, error) {
	if f.failOn == "route" {
		return nil, nil, errFake
	}
	f.routes = append(f.routes, dst.String())
	return []string{"apply route " + dst.String()}, []string{"undo route " + dst.String()}, nil
}

func (f *fakeConfigurer) SetDNS(iface string, servers []net.IP) ([]string, []string, error) {
	if strings.Contains(iface, f.failOn) {
		return nil, nil, errFake
	}
	var ips []string
	for _, s := range servers {
		ips = append(ips, s.String())
	}
	f.dns = append(f.dns, iface+"="+strings.Join(ips, ","))
	return []string{"apply dns " + iface}, []string{"undo dns " + iface}, nil
}

func (f *fakeConfigurer) ListInterfaces() ([]InterfaceInfo, error) {
	return f.ifaces, nil
}

var errFake = errFakeType{}

type errFakeType struct{}

func (errFakeType) Error() string { return "fake failure" }

func newTestManager(t *testing.T, cfg *fakeConfigurer) *Manager {
	t.Helper()
	j, err := failsafe.Open(filepath(t))
	if err != nil {
		t.Fatal(err)
	}
	return NewManager(cfg, j)
}

func filepath(t *testing.T) string {
	return t.TempDir() + "/journal.json"
}

func TestApplyJournalsInOrderAndRollsBackReversed(t *testing.T) {
	cfg := &fakeConfigurer{ifaces: []InterfaceInfo{{Name: "Ethernet"}}}
	m := newTestManager(t, cfg)

	err := m.Apply(Desired{
		AdapterName:        "Toppa",
		TunnelIP:           net.IPv4(10, 111, 0, 1),
		TunnelPrefixLen:    32,
		DefaultRouteMetric: 5,
		DNS:                []net.IP{net.IPv4(10, 111, 0, 1)},
		RewritePhysicalDNS: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Journal must show: address, two routes, tunnel dns, physical dns.
	outstanding := m.journal.Outstanding()
	if len(outstanding) != 5 {
		t.Fatalf("expected 5 journaled mutations, got %d", len(outstanding))
	}
	if !strings.Contains(outstanding[0].Description, "10.111.0.1") ||
		!strings.Contains(outstanding[1].Description, "0.0.0.0/0") ||
		!strings.Contains(outstanding[2].Description, "::/0") {
		t.Fatalf("unexpected journal order: %+v", outstanding[:3])
	}

	var undos []string
	m.journal.RollbackAll(func(e failsafe.Entry) error {
		undos = append(undos, e.Undo...)
		return nil
	})
	// Reverse order: physical dns first, address last.
	if !strings.HasPrefix(undos[0], "undo dns Ethernet") {
		t.Fatalf("first undo should be the physical DNS rewrite: %v", undos)
	}
	if !strings.HasPrefix(undos[len(undos)-1], "undo ip") {
		t.Fatalf("last undo should be the interface address: %v", undos)
	}
}

func TestApplyFailureLeavesJournalForReconcile(t *testing.T) {
	cfg := &fakeConfigurer{ifaces: []InterfaceInfo{{Name: "Ethernet"}}, failOn: "route"}
	m := newTestManager(t, cfg)

	err := m.Apply(Desired{
		AdapterName:        "Toppa",
		TunnelIP:           net.IPv4(10, 111, 0, 1),
		TunnelPrefixLen:    32,
		DefaultRouteMetric: 5,
	})
	if err == nil {
		t.Fatal("expected route failure to surface")
	}

	// Address mutation was applied and journaled; reconcile must undo it.
	outstanding := m.journal.Outstanding()
	if len(outstanding) != 1 || !strings.Contains(outstanding[0].Description, "10.111.0.1") {
		t.Fatalf("address mutation not journaled for reconcile: %+v", outstanding)
	}
	rolled, err := m.Reconcile()
	if err != nil || rolled != 1 {
		t.Fatalf("reconcile rolled=%d err=%v", rolled, err)
	}
	if len(cfg.ips) != 1 {
		t.Fatalf("unexpected ip mutations: %v", cfg.ips)
	}
}

func TestPhysicalDNSRewriteSkipsTunnelAdapter(t *testing.T) {
	cfg := &fakeConfigurer{ifaces: []InterfaceInfo{{Name: "Toppa"}, {Name: "Wi-Fi"}}}
	m := newTestManager(t, cfg)
	if err := m.Apply(Desired{
		AdapterName:        "Toppa",
		TunnelIP:           net.IPv4(10, 111, 0, 1),
		TunnelPrefixLen:    32,
		DefaultRouteMetric: 5,
		DNS:                []net.IP{net.IPv4(10, 111, 0, 1)},
		RewritePhysicalDNS: true,
	}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(cfg.dns, ";")
	if !strings.Contains(joined, "Toppa=") || !strings.Contains(joined, "Wi-Fi=10.111.0.1") {
		t.Fatalf("dns rewrite wrong: %v", cfg.dns)
	}
	if strings.Count(joined, "Toppa=") != 1 {
		t.Fatalf("tunnel adapter rewritten as physical: %v", cfg.dns)
	}
}
