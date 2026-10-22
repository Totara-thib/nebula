package nebula

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DefinedNet/dnsconfig"
	"github.com/slackhq/nebula/cert"
	cert_test "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay/overlaytest"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setHostDNSConfig pokes the `dns` stanza straight into Settings, the same
// shortcut setDnsConfig and setStatsConfig take.
func setHostDNSConfig(c *config.C, dns map[string]any) {
	c.Settings["dns"] = dns
}

// loadHostDNSConfig loads the whole stanza, the way hostDNS.loadConfig sees it.
func loadHostDNSConfig(c *config.C) (hostDNSConfig, error) {
	opts, optsErr := loadIdentityConfig(c)
	goal, goalErr := loadHostDNSGoal(c, c.GetBool("tun.disabled", false))
	return hostDNSConfig{hostDNSOptions: opts, hostDNSGoal: goal}, joinDNSErrors(optsErr, goalErr)
}

func TestLoadHostDNSConfig_disabled(t *testing.T) {
	c := config.NewC(test.NewLogger())

	cfg, err := loadHostDNSConfig(c)
	require.NoError(t, err)
	assert.False(t, cfg.enabled)
	assert.Equal(t, defaultHostDNSIdentity, cfg.Identity, "a disabled stanza still names its identity")

	// The resolver keys are not even looked at while disabled.
	setHostDNSConfig(c, map[string]any{"enabled": false, "nameservers": []any{"not an ip"}})
	cfg, err = loadHostDNSConfig(c)
	require.NoError(t, err)
	assert.False(t, cfg.enabled)

	// The identity config is: a disabled stanza is what a start after a
	// crash may look like, and it has to know which identity and marker to
	// clean up under.
	marker := filepath.Join(t.TempDir(), "nebula.dns")
	setHostDNSConfig(c, map[string]any{"enabled": false, "identity": "nebula-two", "marker_path": marker})
	cfg, err = loadHostDNSConfig(c)
	require.NoError(t, err)
	assert.Equal(t, "nebula-two", cfg.Identity)
	assert.Equal(t, marker, cfg.MarkerPath)

	setHostDNSConfig(c, map[string]any{"enabled": false, "identity": "nebula/two"})
	_, err = loadHostDNSConfig(c)
	require.ErrorContains(t, err, "dns.identity is not usable")
}

func TestLoadHostDNSConfig_split(t *testing.T) {
	c := config.NewC(test.NewLogger())
	setHostDNSConfig(c, map[string]any{
		"enabled":        true,
		"nameservers":    []any{"192.168.100.1", "fd00::1"},
		"search_domains": []any{"Mesh.Example.com"},
	})

	cfg, err := loadHostDNSConfig(c)
	require.NoError(t, err)
	assert.True(t, cfg.enabled)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.100.1"), netip.MustParseAddr("fd00::1")}, cfg.dns.Nameservers)

	// Domains reach dnsconfig as written; it canonicalizes on its own.
	assert.Equal(t, []string{"Mesh.Example.com"}, cfg.dns.SearchDomains)

	// match_domains defaults to search_domains: split DNS, not a takeover.
	assert.Equal(t, cfg.dns.SearchDomains, cfg.dns.MatchDomains)
	assert.True(t, cfg.dns.IsSplit())

	assert.Equal(t, defaultHostDNSIdentity, cfg.Identity)
	assert.Empty(t, cfg.MarkerPath)
}

func TestLoadHostDNSConfig_catchAll(t *testing.T) {
	c := config.NewC(test.NewLogger())
	setHostDNSConfig(c, map[string]any{
		"enabled":        true,
		"nameservers":    []any{"192.168.100.1"},
		"search_domains": []any{"mesh.example.com"},
		"match_domains":  []any{},
	})

	cfg, err := loadHostDNSConfig(c)
	require.NoError(t, err)
	assert.Empty(t, cfg.dns.MatchDomains)
	assert.False(t, cfg.dns.IsSplit(), "an explicitly empty match_domains is the catch-all opt-in")
	assert.Equal(t, []string{"mesh.example.com"}, cfg.dns.SearchDomains)
}

func TestLoadHostDNSConfig_matchDomainsOnly(t *testing.T) {
	c := config.NewC(test.NewLogger())
	setHostDNSConfig(c, map[string]any{
		"enabled":       true,
		"nameservers":   []any{"192.168.100.1"},
		"match_domains": []any{"mesh.example.com"},
	})

	cfg, err := loadHostDNSConfig(c)
	require.NoError(t, err)
	assert.Empty(t, cfg.dns.SearchDomains)
	assert.True(t, cfg.dns.IsSplit())
}

func TestLoadHostDNSConfig_identity(t *testing.T) {
	c := config.NewC(test.NewLogger())
	marker := filepath.Join(t.TempDir(), "dns.applied")
	setHostDNSConfig(c, map[string]any{
		"enabled":       true,
		"nameservers":   []any{"192.168.100.1"},
		"match_domains": []any{"mesh.example.com"},
		"identity":      "nebula-corp",
		"marker_path":   marker,
	})

	cfg, err := loadHostDNSConfig(c)
	require.NoError(t, err)
	assert.Equal(t, "nebula-corp", cfg.Identity)
	assert.Equal(t, marker, cfg.MarkerPath)
}

func TestLoadHostDNSConfig_errors(t *testing.T) {
	// expected lists every message the stanza should produce, in order.
	// loadHostDNSConfig keeps checking after a key fails, so one bad stanza
	// can report several problems at once.
	tests := []struct {
		name     string
		tun      map[string]any
		dns      map[string]any
		expected []string
	}{
		{
			name: "tun disabled",
			tun:  map[string]any{"disabled": true},
			dns:  map[string]any{"enabled": true, "nameservers": []any{"192.168.100.1"}},
			expected: []string{"dns.enabled requires a tun device, but tun.disabled is true",
				`dns requires search_domains or match_domains; set "match_domains: []" to send every query to dns.nameservers`},
		},
		{
			name:     "no nameservers",
			dns:      map[string]any{"enabled": true, "match_domains": []any{"a.example.com"}},
			expected: []string{"dns.nameservers must have at least one entry"},
		},
		{
			name:     "empty nameservers",
			dns:      map[string]any{"enabled": true, "nameservers": []any{}, "match_domains": []any{"a.example.com"}},
			expected: []string{"dns.nameservers must have at least one entry"},
		},
		{
			name: "unparseable nameserver",
			dns:  map[string]any{"enabled": true, "nameservers": []any{"192.168.100.1", "nope"}},
			expected: []string{"entry 2 in dns.nameservers is not an IP address (map[addr:nope]): ParseAddr(\"nope\"): unable to parse IP",
				`dns requires search_domains or match_domains; set "match_domains: []" to send every query to dns.nameservers`},
		},
		{
			name: "nameserver with a port",
			dns:  map[string]any{"enabled": true, "nameservers": []any{"192.168.100.1:53"}},
			expected: []string{"entry 1 in dns.nameservers is not an IP address (map[addr:192.168.100.1:53]): ParseAddr(\"192.168.100.1:53\"): unexpected character (at \":53\")",
				`dns requires search_domains or match_domains; set "match_domains: []" to send every query to dns.nameservers`},
		},
		{
			name: "zone scoped nameserver",
			dns:  map[string]any{"enabled": true, "nameservers": []any{"fe80::1%eth0"}},
			expected: []string{"entry 1 in dns.nameservers is zone-scoped, which is not supported: fe80::1%eth0",
				`dns requires search_domains or match_domains; set "match_domains: []" to send every query to dns.nameservers`},
		},
		{
			// Names themselves are dnsconfig's to judge, once the stanza is
			// otherwise whole.
			name:     "bad search domain",
			dns:      map[string]any{"enabled": true, "nameservers": []any{"192.168.100.1"}, "search_domains": []any{"-nope.example.com"}},
			expected: []string{`dns is not a valid DNS configuration (map[]): dnsconfig: SearchDomains[0] ("-nope.example.com") is not a valid domain: "-nope.example.com.": label "-nope" starts or ends with hyphen`},
		},
		{
			name:     "bad match domain",
			dns:      map[string]any{"enabled": true, "nameservers": []any{"192.168.100.1"}, "match_domains": []any{"nope-.example.com"}},
			expected: []string{`dns is not a valid DNS configuration (map[]): dnsconfig: MatchDomains[0] ("nope-.example.com") is not a valid domain: "nope-.example.com.": label "nope-" starts or ends with hyphen`},
		},
		{
			name:     "nameserver that cannot serve DNS",
			dns:      map[string]any{"enabled": true, "nameservers": []any{"0.0.0.0"}, "match_domains": []any{"mesh.example.com"}},
			expected: []string{`dns is not a valid DNS configuration (map[]): dnsconfig: Nameservers[0] (0.0.0.0) is an unspecified, multicast, or broadcast address, which cannot serve DNS`},
		},
		{
			name:     "search domain outside match domains",
			dns:      map[string]any{"enabled": true, "nameservers": []any{"192.168.100.1"}, "search_domains": []any{"other.example.com"}, "match_domains": []any{"mesh.example.com"}},
			expected: []string{`dns is not a valid DNS configuration (map[]): dnsconfig: SearchDomains[0] ("other.example.com") is not under any MatchDomains entry`},
		},
		{
			name:     "empty search domain",
			dns:      map[string]any{"enabled": true, "nameservers": []any{"192.168.100.1"}, "search_domains": []any{"mesh.example.com", ""}},
			expected: []string{"entry 2 in dns.search_domains is empty"},
		},
		{
			// The stanza spells catch-all by emptying match_domains, so the
			// root domain is named as that mistake rather than as dnsconfig's
			// own rule about its list.
			name:     "root match domain",
			dns:      map[string]any{"enabled": true, "nameservers": []any{"192.168.100.1"}, "match_domains": []any{"."}},
			expected: []string{`entry 1 in dns.match_domains is the root domain; set "match_domains: []" to send every query to dns.nameservers`},
		},
		{
			// A one entry list written without the leading dash. The empty
			// match set it used to produce is the opt in to catch-all DNS, so
			// this has to be an error rather than a silent widening.
			name:     "match domains written as a scalar",
			dns:      map[string]any{"enabled": true, "nameservers": []any{"192.168.100.1"}, "match_domains": "mesh.example.com"},
			expected: []string{"dns.match_domains must be a list, but wasn't: mesh.example.com"},
		},
		{
			name:     "search domains written as a scalar",
			dns:      map[string]any{"enabled": true, "nameservers": []any{"192.168.100.1"}, "search_domains": "mesh.example.com", "match_domains": []any{}},
			expected: []string{"dns.search_domains must be a list, but wasn't: mesh.example.com"},
		},
		{
			name:     "nameservers written as a scalar",
			dns:      map[string]any{"enabled": true, "nameservers": "192.168.100.1", "match_domains": []any{}},
			expected: []string{"dns.nameservers must be a list, but wasn't: 192.168.100.1"},
		},
		{
			name:     "no domains at all",
			dns:      map[string]any{"enabled": true, "nameservers": []any{"192.168.100.1"}},
			expected: []string{`dns requires search_domains or match_domains; set "match_domains: []" to send every query to dns.nameservers`},
		},
		{
			name:     "empty identity",
			dns:      map[string]any{"enabled": true, "nameservers": []any{"192.168.100.1"}, "match_domains": []any{"a.example.com"}, "identity": ""},
			expected: []string{"dns.identity is not usable: identity is required"},
		},
		{
			// dnsconfig uses it as a file and registry key name, so it is
			// narrower than an arbitrary string.
			name:     "identity with a path separator",
			dns:      map[string]any{"enabled": true, "nameservers": []any{"192.168.100.1"}, "match_domains": []any{"a.example.com"}, "identity": "nebula/two"},
			expected: []string{`dns.identity is not usable: identity "nebula/two" must match ^[a-z0-9][a-z0-9._-]{0,62}$`},
		},
		{
			name:     "relative marker path",
			dns:      map[string]any{"enabled": true, "nameservers": []any{"192.168.100.1"}, "match_domains": []any{"a.example.com"}, "marker_path": "dns.applied"},
			expected: []string{"dns.marker_path must be an absolute path: dns.applied"},
		},
		{
			// Every bad entry in a list is reported, not just the first.
			name: "every bad nameserver",
			dns: map[string]any{
				"enabled":       true,
				"nameservers":   []any{"nope", "192.168.100.1", "fe80::1%eth0"},
				"match_domains": []any{"a.example.com"},
			},
			expected: []string{
				`entry 1 in dns.nameservers is not an IP address (map[addr:nope]): ParseAddr("nope"): unable to parse IP`,
				"entry 3 in dns.nameservers is zone-scoped, which is not supported: fe80::1%eth0",
			},
		},
		{
			// And every bad key, so one pass over the stanza is enough. The
			// identity config errors come first, in stanza order, whether or not the
			// resolver keys are also broken.
			name: "every bad key",
			dns: map[string]any{
				"enabled":        true,
				"nameservers":    []any{"nope"},
				"search_domains": []any{""},
				"identity":       "",
				"marker_path":    "dns.applied",
			},
			expected: []string{
				"dns.identity is not usable: identity is required",
				"dns.marker_path must be an absolute path: dns.applied",
				`entry 1 in dns.nameservers is not an IP address (map[addr:nope]): ParseAddr("nope"): unable to parse IP`,
				"entry 1 in dns.search_domains is empty",
			},
		},
		{
			// A rejected search_domains must not also be blamed for leaving
			// match_domains undecidable; that would be a second error the
			// operator did not make.
			name: "bad search domain does not cascade",
			dns: map[string]any{
				"enabled":        true,
				"nameservers":    []any{"192.168.100.1"},
				"search_domains": []any{""},
			},
			expected: []string{"entry 1 in dns.search_domains is empty"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := config.NewC(test.NewLogger())
			if tt.tun != nil {
				c.Settings["tun"] = tt.tun
			}
			setHostDNSConfig(c, tt.dns)

			_, err := loadHostDNSConfig(c)
			require.EqualError(t, err, strings.Join(tt.expected, "\n"))
		})
	}
}

// TestLoadHostDNSConfig_listWrittenAsAScalar walks the real YAML parser, since
// this one is about the shape the decoder hands back rather than about the
// values. Read with config.C.GetStringSlice, which falls back to its default
// for a non list, this stanza would load clean with no match domains at all -
// the explicit opt in to catch-all DNS, so an operator asking for split DNS
// would get every query on the host pointed at dns.nameservers instead.
func TestLoadHostDNSConfig_listWrittenAsAScalar(t *testing.T) {
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(`
dns:
  enabled: true
  nameservers:
    - 192.168.100.1
  match_domains: mesh.example.com
`))

	_, err := loadHostDNSConfig(c)
	require.EqualError(t, err, "dns.match_domains must be a list, but wasn't: mesh.example.com")
}

// TestLoadHostDNSConfig_loneErrorIsNotWrapped pins that a stanza with exactly
// one problem hands that error back as itself. main.go logs it through
// util.LogWithContextIfNeeded, whose type switch does not unwrap, so joining a
// lone *util.ContextualError would drop its fields from the log line.
func TestLoadHostDNSConfig_loneErrorIsNotWrapped(t *testing.T) {
	c := config.NewC(test.NewLogger())
	setHostDNSConfig(c, map[string]any{
		"enabled":       true,
		"nameservers":   []any{"nope"},
		"match_domains": []any{"a.example.com"},
	})

	_, err := loadHostDNSConfig(c)
	ce, ok := err.(*util.ContextualError) //nolint:errorlint // the caller's type switch does not unwrap either
	require.True(t, ok, "a lone error must reach the caller unwrapped")
	assert.Equal(t, "entry 1 in dns.nameservers is not an IP address", ce.Context)
	assert.Equal(t, m{"addr": "nope"}, ce.Fields)
}

// fakeDNS models the dnsconfig.Manager goal and close bookkeeping the
// controller depends on. A recorded goal waits for Close's cleanup unless
// workerRuns converges it at once, as a worker that reached its attempt
// would. heldElsewhere models another live Manager holding the identity:
// nothing converges, and Close leaves the holder's configuration in place.
type fakeDNS struct {
	opts          dnsconfig.Options
	setErr        error
	closeErr      error
	workerRuns    bool
	heldElsewhere bool
	// setAttemptErr fails every attempt at a Set goal that workerRuns makes.
	setAttemptErr error
	// beforeSet runs at the start of Set; returning false fails it.
	beforeSet func() bool

	mu       sync.Mutex
	calls    []string
	setCalls []dnsconfig.Config
	status   dnsconfig.Status
}

func (f *fakeDNS) Set(c dnsconfig.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "set")
	if f.beforeSet != nil && !f.beforeSet() {
		return errors.New("beforeSet check failed")
	}
	if f.setErr != nil {
		return f.setErr
	}
	f.setCalls = append(f.setCalls, c)
	f.status.Goal = dnsconfig.GoalSet
	f.status.Desired = c
	f.status.Converged = false
	if f.workerRuns && !f.heldElsewhere {
		if f.setAttemptErr != nil {
			f.status.LastError = f.setAttemptErr
		} else {
			f.status.Converged = true
			f.status.LastConvergedCleared = false
		}
	}
	return nil
}

func (f *fakeDNS) Clear() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "clear")
	f.status.Goal = dnsconfig.GoalClear
	f.status.Desired = dnsconfig.Config{}
	f.status.Converged = false
	if f.workerRuns && !f.heldElsewhere {
		f.status.Converged = true
		f.status.LastConvergedCleared = true
	}
	return nil
}

// Close owes cleanup for any Set and for a Clear that has not converged, as
// dnsconfig's does, and reports that cleanup in Converged: it undoes a Set
// goal and completes a Clear goal.
func (f *fakeDNS) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "close")
	owed := f.status.Goal != dnsconfig.GoalNone &&
		!(f.status.Goal == dnsconfig.GoalClear && f.status.Converged)
	if owed && f.heldElsewhere {
		return dnsconfig.ErrManagerAlreadyRunning
	}
	if owed {
		f.status.Converged = f.status.Goal == dnsconfig.GoalClear && f.closeErr == nil
	}
	if f.closeErr != nil {
		return f.closeErr
	}
	if owed {
		f.status.LastConvergedCleared = true
	}
	return nil
}

func (f *fakeDNS) Status() dnsconfig.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *fakeDNS) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// testHostDNSController returns a controller whose managers are handed out
// from fakes in order; a nil fake list hands out fresh ones.
func testHostDNSController(t *testing.T, fakes ...*fakeDNS) (*hostDNSController, *[]*fakeDNS) {
	t.Helper()
	c := newHostDNSController(hostDNSOptions{
		Logger:     slog.Default(),
		Identity:   "nebula.test",
		MarkerPath: filepath.Join(t.TempDir(), ".dns-applied"),
	})
	var built []*fakeDNS
	c.newManager = func(o dnsconfig.Options) (dnsManager, error) {
		f := &fakeDNS{}
		if len(fakes) > 0 {
			f, fakes = fakes[0], fakes[1:]
		}
		f.opts = o
		built = append(built, f)
		return f, nil
	}
	return c, &built
}

func desiredCfg(matchDomains []string, resolvers ...string) dnsconfig.Config {
	var d dnsconfig.Config
	for _, r := range resolvers {
		d.Nameservers = append(d.Nameservers, netip.MustParseAddr(r))
	}
	d.MatchDomains = matchDomains
	return d
}

func TestHostDNSController_apply(t *testing.T) {
	fake := &fakeDNS{}
	c, _ := testHostDNSController(t, fake)
	// dnsconfig may write as soon as the goal is recorded
	fake.beforeSet = c.markerExists

	desired := desiredCfg([]string{"example.internal"}, "240.0.0.1")
	c.Apply(desired, "nebula1")

	assert.Equal(t, []dnsconfig.Config{desired}, fake.setCalls)
	assert.Equal(t, "nebula1", fake.opts.InterfaceName, "tun device must reach the manager options")
	assert.Equal(t, "nebula.test", fake.opts.Identity)
	assert.Equal(t, hostDNSShutdownTimeout, fake.opts.ShutdownTimeout)
	assert.NotNil(t, fake.opts.Logger)
}

func TestHostDNSController_applyIdempotent(t *testing.T) {
	c, built := testHostDNSController(t)

	c.Apply(desiredCfg([]string{"example.internal"}, "240.0.0.1"), "nebula1")
	c.Apply(desiredCfg([]string{"example.internal"}, "240.0.0.1"), "nebula1")

	// A changed config, or the same one after a deactivate, is a new goal
	c.Apply(desiredCfg([]string{"example.internal"}, "240.0.0.2"), "nebula1")
	c.Deactivate()
	c.Apply(desiredCfg([]string{"example.internal"}, "240.0.0.2"), "nebula1")

	require.Len(t, *built, 1)
	assert.Equal(t, []string{"set", "set", "clear", "set"}, (*built)[0].callList())
}

func TestHostDNSController_applyZeroDeactivates(t *testing.T) {
	c, built := testHostDNSController(t)

	c.Apply(desiredCfg(nil, "240.0.0.1"), "nebula1")
	c.Apply(dnsconfig.Config{}, "nebula1")
	assert.Equal(t, []string{"set", "clear"}, (*built)[0].callList())
}

func TestHostDNSController_applySetRefused(t *testing.T) {
	fake := &fakeDNS{setErr: dnsconfig.ErrInterfaceRequired}
	c, _ := testHostDNSController(t, fake)

	c.Apply(desiredCfg(nil, "240.0.0.1"), "")
	assert.False(t, c.markerExists(), "a refused Set changed nothing, so it must not leave a marker")

	// The goal was not recorded, so the next Apply tries again
	fake.setErr = nil
	c.Apply(desiredCfg(nil, "240.0.0.1"), "")
	assert.Equal(t, []string{"set", "set"}, fake.callList())
}

// A refused Set leaves alone a marker it did not write: a predecessor's
// marker still has a recovery to drive.
func TestHostDNSController_applySetRefusedKeepsAnEarlierMarker(t *testing.T) {
	c, _ := testHostDNSController(t, &fakeDNS{setErr: dnsconfig.ErrInterfaceRequired})
	require.NoError(t, os.WriteFile(c.opts.MarkerPath, []byte("applied\n"), 0o600))

	c.Apply(desiredCfg(nil, "240.0.0.1"), "")
	assert.True(t, c.markerExists())
}

// TestHostDNSController_markerNeverWrittenThroughALink pins the marker to
// dnsconfig's host lock rule: root creates it at an operator-chosen path, so a
// link planted there is never followed. The planted link is not a marker
// either, so it drives no recovery.
func TestHostDNSController_markerNeverWrittenThroughALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink needs a privilege on Windows")
	}
	target := filepath.Join(t.TempDir(), "target")

	c, built := testHostDNSController(t)
	require.NoError(t, os.Symlink(target, c.opts.MarkerPath))
	assert.False(t, c.markerExists(), "a link is not a marker")

	c.Apply(desiredCfg(nil, "240.0.0.1"), "nebula1")
	assert.NoFileExists(t, target, "the link must not be followed")
	assert.False(t, c.markerExists())
	assert.Equal(t, []string{"set"}, (*built)[0].callList(), "a marker that could not be written does not stop the goal")

	// A Deactivate with no manager is driven by the marker alone.
	d, built := testHostDNSController(t)
	require.NoError(t, os.Symlink(target, d.opts.MarkerPath))
	d.Deactivate()
	assert.Empty(t, *built, "a link must not look like a crash to recover from")
}

func TestHostDNSController_deactivateWithoutMarkerIsLazy(t *testing.T) {
	c, built := testHostDNSController(t)

	// Hosts that don't use the feature shouldn't touch dnsconfig
	c.Deactivate()
	c.Close()
	assert.Empty(t, *built)
}

func TestHostDNSController_deactivateRecoversFromMarker(t *testing.T) {
	c, built := testHostDNSController(t)
	require.NoError(t, os.WriteFile(c.opts.MarkerPath, []byte("applied\n"), 0o600))

	// A leftover marker means a crashed predecessor may have left the host
	// resolver broken; clear even though this config doesn't use DNS.
	c.Deactivate()
	c.Close()
	require.Len(t, *built, 1)
	assert.Equal(t, []string{"clear", "close"}, (*built)[0].callList())
	assert.False(t, c.markerExists())
}

func TestHostDNSController_noMarkerPathWritesNothing(t *testing.T) {
	c, built := testHostDNSController(t)
	c.opts.MarkerPath = ""

	c.Apply(desiredCfg(nil, "240.0.0.1"), "nebula1")
	c.Close()
	require.Len(t, *built, 1)
	assert.Equal(t, []string{"set", "close"}, (*built)[0].callList())
	assert.False(t, c.markerExists())
}

func TestHostDNSController_rebuildsManagerForNewInterface(t *testing.T) {
	c, built := testHostDNSController(t)
	require.NoError(t, os.WriteFile(c.opts.MarkerPath, []byte("applied\n"), 0o600))

	// Crash recovery before the tun device is known builds a manager with
	// no interface; Windows cannot apply through it.
	c.Deactivate()
	c.Apply(desiredCfg(nil, "240.0.0.1"), "nebula1")

	// Same device, or a Deactivate that doesn't know it: no rebuild
	c.Apply(desiredCfg(nil, "240.0.0.2"), "nebula1")
	c.Deactivate()
	c.Close()

	require.Len(t, *built, 2)
	assert.Empty(t, (*built)[0].opts.InterfaceName)
	assert.Equal(t, []string{"clear", "close"}, (*built)[0].callList())
	assert.Equal(t, "nebula1", (*built)[1].opts.InterfaceName)
	assert.Equal(t, []string{"set", "set", "clear", "close"}, (*built)[1].callList())
}

func TestHostDNSController_constructionFailureRetries(t *testing.T) {
	c, _ := testHostDNSController(t)
	attempts := 0
	c.newManager = func(dnsconfig.Options) (dnsManager, error) {
		attempts++
		return nil, errors.New("no backend")
	}

	assert.True(t, c.Apply(desiredCfg(nil, "240.0.0.1"), ""), "a failed build asks for a retry")
	assert.True(t, c.Apply(desiredCfg(nil, "240.0.0.1"), ""))
	c.Close()
	assert.Equal(t, 2, attempts)
	assert.False(t, c.markerExists(), "nothing was ever applied")
}

func TestHostDNSController_unsupportedPlatform(t *testing.T) {
	c, _ := testHostDNSController(t)
	attempts := 0
	c.newManager = func(dnsconfig.Options) (dnsManager, error) {
		attempts++
		return nil, errHostDNSUnsupported
	}

	assert.False(t, c.Apply(desiredCfg(nil, "240.0.0.1"), ""), "an unsupported host never asks for a retry")
	assert.False(t, c.Apply(desiredCfg(nil, "240.0.0.1"), ""))
	c.Close()
	assert.Equal(t, 1, attempts)
	assert.False(t, c.markerExists())
}

func TestHostDNSController_closeRemovesMarker(t *testing.T) {
	c, _ := testHostDNSController(t)

	c.Apply(desiredCfg(nil, "240.0.0.1"), "nebula1")
	require.True(t, c.markerExists())
	c.Close()
	assert.False(t, c.markerExists())
}

func TestHostDNSController_closeKeepsMarkerWhenCleanupFails(t *testing.T) {
	c, _ := testHostDNSController(t, &fakeDNS{closeErr: errors.New("cleanup failed")})

	c.Apply(desiredCfg(nil, "240.0.0.1"), "nebula1")
	c.Close()
	assert.True(t, c.markerExists())
}

// Close reports a restore only when it had something to restore: a manager
// built for a crash-recovery check that found no goal has nothing to undo.
func TestHostDNSController_closeLogsRestoreOnlyWhenOwed(t *testing.T) {
	var logs bytes.Buffer
	c, _ := testHostDNSController(t, &fakeDNS{workerRuns: true})
	c.logger = slog.New(slog.NewTextHandler(&logs, nil))

	c.Apply(desiredCfg(nil, "240.0.0.1"), "nebula1")
	c.Deactivate()
	c.Close()
	assert.NotContains(t, logs.String(), "restored", "a converged Clear left nothing for Close to restore")

	logs.Reset()
	c, _ = testHostDNSController(t)
	c.logger = slog.New(slog.NewTextHandler(&logs, nil))
	c.Apply(desiredCfg(nil, "240.0.0.1"), "nebula1")
	c.Close()
	assert.Contains(t, logs.String(), "restored the previous host DNS config")
}

// While another live manager holds the identity, dnsconfig's Close leaves
// that holder's configuration in place. The marker must stay for a later
// attempt.
func TestHostDNSController_closeKeepsMarkerWhenIdentityHeldElsewhere(t *testing.T) {
	c, _ := testHostDNSController(t, &fakeDNS{heldElsewhere: true})
	require.NoError(t, os.WriteFile(c.opts.MarkerPath, []byte("applied\n"), 0o600))

	c.Deactivate()
	c.Close()
	assert.True(t, c.markerExists())
}

// A converged Clear released the identity, so a Close that fails afterwards
// (backend teardown, lock release) has nothing of ours left to remove.
func TestHostDNSController_closeRemovesMarkerAfterConvergedClear(t *testing.T) {
	c, _ := testHostDNSController(t, &fakeDNS{workerRuns: true, closeErr: errors.New("teardown failed")})

	c.Apply(desiredCfg(nil, "240.0.0.1"), "nebula1")
	c.Deactivate()
	c.Close()
	assert.False(t, c.markerExists())
}

// LastConvergedCleared survives a Set whose attempts all fail. When Close's
// cleanup for that Set fails too, its partial writes may remain, so the
// earlier Clear must not count.
func TestHostDNSController_closeKeepsMarkerWhenSetFailsAfterConvergedClear(t *testing.T) {
	fake := &fakeDNS{workerRuns: true, closeErr: errors.New("cleanup failed")}
	c, _ := testHostDNSController(t, fake)

	c.Apply(desiredCfg(nil, "240.0.0.1"), "nebula1")
	c.Deactivate()
	fake.setAttemptErr = errors.New("attempt failed")
	c.Apply(desiredCfg(nil, "240.0.0.2"), "nebula1")
	c.Close()
	assert.True(t, c.markerExists())
}

// Shutdown closes the controller while a reload may still be finishing;
// nothing it does afterwards may reinstall DNS.
func TestHostDNSController_closeIsTerminal(t *testing.T) {
	c, built := testHostDNSController(t)

	c.Apply(desiredCfg(nil, "240.0.0.1"), "nebula1")
	c.Close()
	c.Apply(desiredCfg(nil, "240.0.0.2"), "nebula1")
	c.Deactivate()
	c.Close()

	require.Len(t, *built, 1)
	assert.Equal(t, []string{"set", "close"}, (*built)[0].callList())
	assert.False(t, c.markerExists())
}

// Shutdown calls Close from another goroutine while a reload may be applying
// config; run under -race.
func TestHostDNSController_concurrentApplyAndClose(t *testing.T) {
	c, built := testHostDNSController(t)

	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			for j := range 50 {
				if (i+j)%3 == 0 {
					c.Deactivate()
				} else {
					c.Apply(desiredCfg(nil, "240.0.0.1"), "nebula1")
				}
			}
		})
	}
	wg.Go(c.Close)
	wg.Wait()

	// Every manager built was closed, and none came after Close
	for _, f := range *built {
		calls := f.callList()
		require.NotEmpty(t, calls)
		assert.Equal(t, "close", calls[len(calls)-1])
	}
	assert.False(t, c.markerExists())
}

// TestHostDNSController_realNoopBackend walks the real dnsconfig.Manager with
// its noop backend forced, which applies nothing and needs no privileges, so
// the lifecycle is exercised against the actual library once rather than only
// against the fake.
func TestHostDNSController_realNoopBackend(t *testing.T) {
	c := newHostDNSController(hostDNSOptions{
		Logger:     slog.Default(),
		Identity:   "nebula.test.noop",
		MarkerPath: filepath.Join(t.TempDir(), ".dns-applied"),
	})
	c.newManager = func(o dnsconfig.Options) (dnsManager, error) {
		o.ForceBackend = dnsconfig.BackendNoop
		return dnsconfig.New(t.Context(), o)
	}

	c.Apply(desiredCfg([]string{"example.internal"}, "240.0.0.1"), "nebula1")
	require.NotNil(t, c.mgr)
	st := c.mgr.Status()
	assert.Equal(t, dnsconfig.GoalSet, st.Goal)
	assert.True(t, c.markerExists())

	c.Close()
	assert.Nil(t, c.mgr)
	assert.False(t, c.markerExists(), "the noop backend's Clear converges")
}

func TestHostDNS_reload(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.LoadString(`
dns:
  enabled: true
  nameservers:
    - 192.168.100.1
  search_domains:
    - mesh.example.com
`))

	s, err := newHostDNSFromConfig(l, c, overlaytest.NoopTun{})
	require.NoError(t, err)
	assert.True(t, s.config().enabled)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.100.1")}, s.config().dns.Nameservers)

	require.NoError(t, c.ReloadConfigString(`
dns:
  enabled: true
  nameservers:
    - 192.168.100.2
  search_domains:
    - mesh.example.com
`).Err)
	assert.True(t, s.config().enabled)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.100.2")}, s.config().dns.Nameservers)

	require.NoError(t, c.ReloadConfigString("dns:\n  enabled: false\n").Err)
	assert.False(t, s.config().enabled)
}

func TestHostDNS_reload_invalidInitial(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.LoadString("dns:\n  enabled: true\n"))

	// A broken stanza is reported but does not stop the caller. The returned
	// hostDNS is usable with host DNS left off, and the reload callback is
	// already registered so a HUP can fix it.
	s, err := newHostDNSFromConfig(l, c, overlaytest.NoopTun{})
	require.EqualError(t, err, "dns.nameservers must have at least one entry\n"+
		`dns requires search_domains or match_domains; set "match_domains: []" to send every query to dns.nameservers`)
	require.NotNil(t, s)
	assert.False(t, s.config().enabled, "a config that did not load must leave host DNS off")

	// Both ends of the lifecycle must be safe to call in that state. With no
	// marker, the Deactivate that Start states touches nothing.
	built := fakeControllers(s)
	s.Start()
	require.Len(t, *built, 1)
	assert.Equal(t, []string{"deactivate"}, (*built)[0].callList(), "Start must not apply a config that did not load")
	s.Restore()

	require.NoError(t, c.ReloadConfigString(`
dns:
  enabled: true
  nameservers:
    - 192.168.100.1
  match_domains: []
`).Err)
	assert.True(t, s.config().enabled)
	assert.False(t, s.config().dns.IsSplit())
}

// TestHostDNS_reload_invalidInitialStillRecovers pins that a broken stanza
// does not cost crash recovery: the identity and marker loaded, so Start
// deactivates under them and the controller can clear what a crash left.
func TestHostDNS_reload_invalidInitialStillRecovers(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	marker := filepath.Join(t.TempDir(), "dns.applied")
	setHostDNSConfig(c, map[string]any{"enabled": true, "identity": "nebula-two", "marker_path": marker})

	s, err := newHostDNSFromConfig(l, c, overlaytest.NoopTun{})
	require.Error(t, err)
	assert.False(t, s.config().enabled)

	built := fakeControllers(s)
	s.Start()
	require.Len(t, *built, 1)
	assert.Equal(t, "nebula-two", (*built)[0].opts.Identity)
	assert.Equal(t, marker, (*built)[0].opts.MarkerPath)
	assert.Equal(t, []string{"deactivate"}, (*built)[0].callList())
	s.Restore()
}

// TestHostDNS_reload_invalidInitialControllerKey pins that recovery needs
// both identity values: without a usable identity there is nothing to recover
// under, so Start leaves the host alone.
func TestHostDNS_reload_invalidInitialControllerKey(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	setHostDNSConfig(c, map[string]any{"enabled": false, "identity": "nebula/two", "marker_path": filepath.Join(t.TempDir(), "dns.applied")})

	s, err := newHostDNSFromConfig(l, c, overlaytest.NoopTun{})
	require.ErrorContains(t, err, "dns.identity is not usable")

	built := fakeControllers(s)
	s.Start()
	assert.Empty(t, *built, "Start must not touch the host without an identity")
	s.Restore()
}

// TestHostDNS_reload_invalidInitialRecoversOnALaterFailedReload pins that the
// identity config is kept from any failed load until a configuration loads,
// not just the first: a HUP that fixes the identity but not the goal still
// fails, and still hands Start what it needs to recover.
func TestHostDNS_reload_invalidInitialRecoversOnALaterFailedReload(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	marker := filepath.Join(t.TempDir(), "dns.applied")
	setHostDNSConfig(c, map[string]any{"enabled": true, "identity": "nebula/two", "marker_path": marker})

	s, err := newHostDNSFromConfig(l, c, overlaytest.NoopTun{})
	require.ErrorContains(t, err, "dns.identity is not usable")
	assert.Nil(t, s.runCfg, "nothing usable to keep yet")

	setHostDNSConfig(c, map[string]any{"enabled": true, "identity": "nebula-two", "marker_path": marker})
	require.EqualError(t, s.reload(c), "dns.nameservers must have at least one entry\n"+
		`dns requires search_domains or match_domains; set "match_domains: []" to send every query to dns.nameservers`)
	s.reloads.Wait()
	assert.False(t, s.config().enabled)
	assert.Equal(t, "nebula-two", s.config().Identity)

	built := fakeControllers(s)
	s.Start()
	require.Len(t, *built, 1)
	assert.Equal(t, "nebula-two", (*built)[0].opts.Identity)
	assert.Equal(t, marker, (*built)[0].opts.MarkerPath)
	assert.Equal(t, []string{"deactivate"}, (*built)[0].callList())
	s.Restore()
}

// TestHostDNS_reload_failureKeepsTheRunningConfig pins that once a
// configuration has loaded, a HUP that fails leaves it in place.
func TestHostDNS_reload_failureKeepsTheRunningConfig(t *testing.T) {
	s, c, _ := fakeHostDNS(t, nil)
	before := s.config()

	setHostDNSConfig(c, map[string]any{"enabled": true, "marker_path": s.markerPath()})
	require.Error(t, s.reload(c))
	assert.Equal(t, before, s.config())
}

// TestHostDNS_reload_reportsAFailure pins that a stanza a HUP can not load
// fails the reload rather than being swallowed: config.ReloadResult is how an
// operator hears about it.
func TestHostDNS_reload_reportsAFailure(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.LoadString("dns:\n  enabled: false\n"))

	_, err := newHostDNSFromConfig(l, c, overlaytest.NoopTun{})
	require.NoError(t, err)

	r := c.ReloadConfigString("dns:\n  enabled: true\n")
	require.NoError(t, r.Err)
	assert.True(t, r.Failed, "a stanza that does not load must fail the reload")
}

// fakeController records the goals hostDNS hands a hostDNSController. What
// the controller then does with them - the lazy Manager, the marker, the
// unsupported memo - is covered by the TestHostDNSController tests above.
type fakeController struct {
	opts hostDNSOptions

	// failBuilds is how many Apply or Deactivate calls still report that no
	// manager could be built, the way the real controller does.
	failBuilds int

	mu      sync.Mutex
	calls   []string
	applied []dnsconfig.Config
	ifaces  []string
}

func (f *fakeController) Apply(desired dnsconfig.Config, tunDev string) (retry bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "apply")
	f.applied = append(f.applied, desired)
	f.ifaces = append(f.ifaces, tunDev)
	return f.failBuild()
}

func (f *fakeController) Deactivate() (retry bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "deactivate")
	return f.failBuild()
}

func (f *fakeController) failBuild() bool {
	if f.failBuilds == 0 {
		return false
	}
	f.failBuilds--
	return true
}

func (f *fakeController) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "close")
}

func (f *fakeController) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// fakeHostDNS builds a hostDNS whose controllers are fakes, recorded in
// the order they were built. The stanza is enabled with a marker in a temp dir
// unless dns says otherwise, and the hostDNS is restored at the end of the
// test.
func fakeHostDNS(t *testing.T, dns map[string]any) (*hostDNS, *config.C, *[]*fakeController) {
	t.Helper()

	l := test.NewLogger()
	c := config.NewC(l)
	if dns == nil {
		dns = map[string]any{
			"enabled":       true,
			"nameservers":   []any{"240.0.0.1"},
			"match_domains": []any{"example.internal"},
		}
	}
	if _, ok := dns["marker_path"]; !ok {
		dns["marker_path"] = filepath.Join(t.TempDir(), "dns.applied")
	}
	setHostDNSConfig(c, dns)

	s, err := newHostDNSFromConfig(l, c, overlaytest.NoopTun{})
	require.NoError(t, err)

	built := fakeControllers(s)
	t.Cleanup(s.Restore)
	return s, c, built
}

// fakeControllers makes every controller s builds a fake, recorded in the
// order they were built.
func fakeControllers(s *hostDNS) *[]*fakeController {
	built := &[]*fakeController{}
	var mu sync.Mutex
	s.newController = func(o hostDNSOptions) dnsController {
		mu.Lock()
		defer mu.Unlock()
		f := &fakeController{opts: o}
		*built = append(*built, f)
		return f
	}
	return built
}

func (s *hostDNS) controller() dnsController {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctrl
}

func (s *hostDNS) markerPath() string {
	return s.config().MarkerPath
}

// reloadHostDNS runs a reload of the stanza dns and waits for the converge it
// kicked off, so a test can look at the controller without racing it. The
// marker path the test started with is kept unless dns names one.
func reloadHostDNS(t *testing.T, s *hostDNS, c *config.C, dns map[string]any) {
	t.Helper()
	if _, ok := dns["marker_path"]; !ok {
		dns["marker_path"] = s.markerPath()
	}
	setHostDNSConfig(c, dns)
	require.NoError(t, s.reload(c))
	s.reloads.Wait()
}

func TestHostDNS_retriesUntilAGoalIsRecorded(t *testing.T) {
	s, _, _ := fakeHostDNS(t, nil)
	s.retryBase = time.Millisecond
	f := &fakeController{failBuilds: 2}
	s.newController = func(o hostDNSOptions) dnsController { f.opts = o; return f }

	s.Start()
	require.Eventually(t, func() bool { return len(f.callList()) == 3 }, time.Second, time.Millisecond,
		"two failed builds are retried, the third attempt records the goal")

	s.mu.Lock()
	defer s.mu.Unlock()
	assert.Nil(t, s.retry, "nothing is pending once a goal is recorded")
	assert.Zero(t, s.retryDelay, "the backoff resets")
}

func TestHostDNS_restoreStopsARetry(t *testing.T) {
	s, _, _ := fakeHostDNS(t, nil)
	s.retryBase = time.Hour
	f := &fakeController{failBuilds: 100}
	s.newController = func(o hostDNSOptions) dnsController { f.opts = o; return f }

	s.Start()
	s.mu.Lock()
	require.NotNil(t, s.retry, "a failed build arms a retry")
	s.mu.Unlock()

	s.Restore()
	s.mu.Lock()
	assert.Nil(t, s.retry)
	s.mu.Unlock()
	assert.Equal(t, []string{"apply", "close"}, f.callList())
}

func TestHostDNS_tunDisabledIsFixedAtStart(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	c.Settings["tun"] = map[string]any{"disabled": true}
	setHostDNSConfig(c, map[string]any{
		"enabled":       true,
		"nameservers":   []any{"240.0.0.1"},
		"match_domains": []any{"example.internal"},
	})
	s, err := newHostDNSFromConfig(l, c, nil)
	require.ErrorContains(t, err, "requires a tun device")

	// tun.disabled only takes effect on restart, so flipping it on a reload
	// does not make a device appear.
	c.Settings["tun"] = map[string]any{"disabled": false}
	require.ErrorContains(t, s.reload(c), "requires a tun device")
	assert.False(t, s.config().enabled)
}

func TestHostDNS_startRestore(t *testing.T) {
	s, _, built := fakeHostDNS(t, nil)

	s.Start()
	require.Len(t, *built, 1)
	f := (*built)[0]
	assert.Equal(t, []dnsconfig.Config{desiredCfg([]string{"example.internal"}, "240.0.0.1")}, f.applied)
	assert.Equal(t, []string{overlaytest.NoopTun{}.Name()}, f.ifaces, "the tun device must reach the controller")
	assert.Equal(t, defaultHostDNSIdentity, f.opts.Identity)
	assert.Equal(t, s.markerPath(), f.opts.MarkerPath)
	assert.NotNil(t, f.opts.Logger)

	s.Restore()
	assert.Equal(t, []string{"apply", "close"}, f.callList())
	assert.Nil(t, s.controller())
}

// TestHostDNS_startWhenDisabled pins that a start with the stanza off still
// states the goal: Deactivate is how a crashed predecessor's configuration is
// recovered, and the controller is what decides whether that touches dnsconfig
// at all (it does not without a marker).
func TestHostDNS_startWhenDisabled(t *testing.T) {
	s, _, built := fakeHostDNS(t, map[string]any{"enabled": false})

	s.Start()
	require.Len(t, *built, 1)
	assert.Equal(t, []string{"deactivate"}, (*built)[0].callList())

	s.Restore()
	assert.Equal(t, []string{"deactivate", "close"}, (*built)[0].callList())
}

func TestHostDNS_startWaitsForTheTunDevice(t *testing.T) {
	s, c, built := fakeHostDNS(t, nil)

	// SIGHUP is armed before Control activates the device, so a reload that
	// early only loads its configuration.
	reloadHostDNS(t, s, c, map[string]any{
		"enabled":       true,
		"nameservers":   []any{"240.0.0.2"},
		"match_domains": []any{"example.internal"},
	})
	assert.Empty(t, *built, "nothing may be built before Start")

	s.Start()
	require.Len(t, *built, 1)
	assert.Equal(t, []dnsconfig.Config{desiredCfg([]string{"example.internal"}, "240.0.0.2")}, (*built)[0].applied, "Start must apply the latest configuration")
}

func TestHostDNS_reload_dnsChangeIsANewGoal(t *testing.T) {
	s, c, built := fakeHostDNS(t, nil)
	s.Start()

	reloadHostDNS(t, s, c, map[string]any{
		"enabled":       true,
		"nameservers":   []any{"240.0.0.2"},
		"match_domains": []any{"example.internal"},
	})
	require.Len(t, *built, 1, "the nameservers ride along with the goal")
	assert.Equal(t, []string{"apply", "apply"}, (*built)[0].callList())
	assert.Equal(t, desiredCfg([]string{"example.internal"}, "240.0.0.2"), (*built)[0].applied[1])
}

func TestHostDNS_reload_controllerKeyChangeRebuildsController(t *testing.T) {
	for key, value := range map[string]any{
		"identity":    "nebula-other",
		"marker_path": filepath.Join(t.TempDir(), "other.applied"),
	} {
		t.Run(key, func(t *testing.T) {
			s, c, built := fakeHostDNS(t, nil)
			s.Start()

			reloadHostDNS(t, s, c, map[string]any{
				"enabled":       true,
				"nameservers":   []any{"240.0.0.1"},
				"match_domains": []any{"example.internal"},
				key:             value,
			})
			require.Len(t, *built, 2)
			assert.Equal(t, []string{"apply", "close"}, (*built)[0].callList(), "the old controller reverts what it applied")
			assert.Equal(t, []string{"apply"}, (*built)[1].callList())

			switch key {
			case "identity":
				assert.Equal(t, "nebula-other", (*built)[1].opts.Identity)
			case "marker_path":
				assert.Equal(t, value, (*built)[1].opts.MarkerPath)
			}
		})
	}
}

func TestHostDNS_reload_disableDeactivatesButKeepsController(t *testing.T) {
	s, c, built := fakeHostDNS(t, nil)
	s.Start()

	reloadHostDNS(t, s, c, map[string]any{"enabled": false})
	require.Len(t, *built, 1)
	assert.Equal(t, []string{"apply", "deactivate"}, (*built)[0].callList())
	assert.NotNil(t, s.controller(), "a disable is reversible, so the controller stays")

	// And re-enabling is a new goal through the same controller.
	reloadHostDNS(t, s, c, map[string]any{
		"enabled":       true,
		"nameservers":   []any{"240.0.0.1"},
		"match_domains": []any{"example.internal"},
	})
	require.Len(t, *built, 1)
	assert.Equal(t, []string{"apply", "deactivate", "apply"}, (*built)[0].callList())
}

func TestHostDNS_reload_enableAfterADisabledStart(t *testing.T) {
	s, c, built := fakeHostDNS(t, map[string]any{"enabled": false})
	s.Start()
	require.Len(t, *built, 1)
	assert.Equal(t, []string{"deactivate"}, (*built)[0].callList())

	reloadHostDNS(t, s, c, map[string]any{
		"enabled":       true,
		"nameservers":   []any{"240.0.0.1"},
		"match_domains": []any{"example.internal"},
	})
	require.Len(t, *built, 1)
	assert.Equal(t, []string{"deactivate", "apply"}, (*built)[0].callList())
}

// TestHostDNS_restoreIsFinal pins that nothing applies again after Restore:
// a reload racing shutdown must not reinstall what Restore just removed.
func TestHostDNS_restoreIsFinal(t *testing.T) {
	s, c, built := fakeHostDNS(t, nil)

	s.Start()
	s.Restore()
	reloadHostDNS(t, s, c, map[string]any{
		"enabled":       true,
		"nameservers":   []any{"240.0.0.2"},
		"match_domains": []any{"example.internal"},
	})
	s.Start()
	s.Restore()

	require.Len(t, *built, 1)
	assert.Equal(t, []string{"apply", "close"}, (*built)[0].callList())
}

func TestHostDNS_restoreBeforeStart(t *testing.T) {
	s, _, built := fakeHostDNS(t, nil)

	s.Restore()
	s.Start()
	assert.Empty(t, *built, "Restore before Start latches the host off limits")
}

// Control.Stop calls Restore while a reload may be converging; run under -race.
func TestHostDNS_concurrentReloadAndRestore(t *testing.T) {
	s, _, built := fakeHostDNS(t, nil)
	s.Start()
	marker := s.markerPath()

	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			for j := range 50 {
				if (i+j)%3 == 0 {
					s.converge()
				} else {
					c := config.NewC(s.l)
					setHostDNSConfig(c, map[string]any{
						"enabled":       true,
						"nameservers":   []any{fmt.Sprintf("240.0.0.%d", j%4+1)},
						"match_domains": []any{"example.internal"},
						"marker_path":   marker,
					})
					_ = s.reload(c)
				}
			}
		})
	}
	wg.Go(s.Restore)
	wg.Wait()
	// Reloads converge on their own goroutines; let the stragglers land.
	s.reloads.Wait()

	// Every controller built was closed, and none came after Restore.
	require.Len(t, *built, 1)
	calls := (*built)[0].callList()
	require.NotEmpty(t, calls)
	assert.Equal(t, "close", calls[len(calls)-1])
	assert.Equal(t, 1, strings.Count(strings.Join(calls, " "), "close"))
}

func TestControl_hostDNSStartRestore(t *testing.T) {
	control, _, _ := newReadyControl(t)

	var started, stopped atomic.Bool
	control.hostDNSStart = func() { started.Store(true) }
	control.hostDNSRestore = func() { stopped.Store(true) }

	require.NoError(t, control.Start())
	require.Eventually(t, started.Load, time.Second, 5*time.Millisecond, "Start must launch host DNS")
	assert.False(t, stopped.Load())

	control.Stop()
	assert.True(t, stopped.Load(), "Stop must restore host DNS")
	require.NoError(t, control.Wait())
}

func TestControl_hostDNSRestoreBeforeStart(t *testing.T) {
	control, _, _ := newReadyControl(t)

	var started, stopped atomic.Bool
	control.hostDNSStart = func() { started.Store(true) }
	control.hostDNSRestore = func() { stopped.Store(true) }

	// Never started, so nothing was applied, but Stop still runs the restore
	// path rather than skipping it.
	control.Stop()
	assert.False(t, started.Load())
	assert.True(t, stopped.Load())
}

// TestMain_configTestRejectsABadDNSStanza pins that `nebula -test` fails on a
// dns stanza that every later start would reject. At runtime the stanza is only
// logged, so tunnels come up even when the host's resolver can not be
// configured; that makes the config test the one place an operator hears about
// it before deploying it.
func TestMain_configTestRejectsABadDNSStanza(t *testing.T) {
	l := test.NewLogger()
	dir := t.TempDir()

	before := time.Now().Add(-time.Hour)
	after := time.Now().Add(time.Hour)
	ca, _, caKey, caPEM := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, before, after, nil, nil, nil)
	networks := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}
	_, _, keyPEM, certPEM := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, "config-test", before, after, networks, nil, nil)

	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	configBody := func(dns string) string {
		return fmt.Sprintf(`
pki:
  ca: %s
  cert: %s
  key: %s
firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
%s`, caPath, certPath, keyPath, dns)
	}

	t.Run("a stanza that does not load", func(t *testing.T) {
		c := config.NewC(l)
		require.NoError(t, c.LoadString(configBody(`
dns:
  enabled: true
  nameservers:
    - not-an-address
  match_domains: []
`)))

		// The stanza's own error comes back as itself, the way an unusable
		// pki or firewall stanza does: util.ContextualizeIfNeeded leaves a
		// *util.ContextualError alone so its fields survive to the log line.
		_, err := Main(c, true, "config-test", l, nil)
		require.ErrorContains(t, err, "entry 1 in dns.nameservers is not an IP address")
	})

	t.Run("an identity that dnsconfig will not accept", func(t *testing.T) {
		// Identity is a file and registry key name. dnsconfig.New would
		// refuse it too, but only at runtime, where it is logged and skipped.
		c := config.NewC(l)
		require.NoError(t, c.LoadString(configBody(`
dns:
  enabled: true
  nameservers:
    - 192.168.100.1
  match_domains: []
  identity: "nebula/two"
`)))

		_, err := Main(c, true, "config-test", l, nil)
		require.ErrorContains(t, err, "dns.identity is not usable")
	})

	t.Run("a stanza that loads", func(t *testing.T) {
		c := config.NewC(l)
		require.NoError(t, c.LoadString(configBody(`
dns:
  enabled: true
  nameservers:
    - 192.168.100.1
  search_domains:
    - mesh.example.com
`)))

		control, err := Main(c, true, "config-test", l, nil)
		require.NoError(t, err)
		assert.Nil(t, control, "a config test builds nothing")
	})
}
