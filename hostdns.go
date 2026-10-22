package nebula

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/DefinedNet/dnsconfig"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/util"
)

// This file turns the `dns` stanza into a host DNS configuration and applies it
// to the host OS through a dnsconfig.Manager. It is in three parts: the stanza
// and its parsers, the hostDNSController that owns everything touching the
// host, and the hostDNS wrapper that ties the controller to nebula's config
// reloads and Control lifecycle.

const defaultHostDNSIdentity = "nebula"

// hostDNSConfig is the `dns` stanza, loaded. Its two halves load separately
// because a caller may need one without the other: see hostDNS.loadConfig.
type hostDNSConfig struct {
	// hostDNSOptions is what we need to build a hostDNSController, while
	// hostDNSGoal is what we want the host's DNS resolution to look like.
	hostDNSOptions
	hostDNSGoal
}

// What we want to do to the host's resolver.
type hostDNSGoal struct {
	enabled bool
	dns     dnsconfig.Config
}

// loadIdentityConfig reads dns.identity and dns.marker_path. The Logger is
// left for the caller.
func loadIdentityConfig(c *config.C) (hostDNSOptions, error) {
	var o hostDNSOptions
	var identityErr, markerErr error
	o.Identity, identityErr = parseDNSIdentity(c)
	o.MarkerPath, markerErr = parseDNSMarkerPath(c)
	if err := joinDNSErrors(identityErr, markerErr); err != nil {
		return hostDNSOptions{}, err
	}
	return o, nil
}

// loadHostDNSGoal reads dns.enabled and, when it is on, the desired resolver
// configuration. A disabled stanza ignores the rest of the keys.
//
// tunDisabled is whether this process runs without a tun device.
func loadHostDNSGoal(c *config.C, tunDisabled bool) (hostDNSGoal, error) {
	g := hostDNSGoal{enabled: c.GetBool("dns.enabled", false)}
	if !g.enabled {
		return g, nil
	}

	var tunErr, nameserversErr, domainsErr error
	if tunDisabled {
		tunErr = errors.New("dns.enabled requires a tun device, but tun.disabled is true")
	}
	g.dns.Nameservers, nameserversErr = parseDNSNameservers(c)
	g.dns.SearchDomains, g.dns.MatchDomains, domainsErr = parseDNSDomainLists(c)
	if err := joinDNSErrors(tunErr, nameserversErr, domainsErr); err != nil {
		return hostDNSGoal{}, err
	}

	if err := g.dns.Validate(); err != nil {
		return hostDNSGoal{}, util.NewContextualError("dns is not a valid DNS configuration", nil, err)
	}
	return g, nil
}

// joinDNSErrors reports a batch of validation failures as one error.
//
// A lone error is handed back unwrapped rather than joined, and no errors at
// all is nil.
func joinDNSErrors(errs ...error) error {
	errs = slices.DeleteFunc(slices.Clone(errs), func(err error) bool { return err == nil })
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	}
	return errors.Join(errs...)
}

func parseDNSNameservers(c *config.C) ([]netip.Addr, error) {
	raw, err := c.GetStringSliceStrict("dns.nameservers")
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("dns.nameservers must have at least one entry")
	}

	var errs []error
	out := make([]netip.Addr, 0, len(raw))
	for i, rawAddr := range raw {
		addr, err := netip.ParseAddr(rawAddr)
		if err != nil {
			errs = append(errs, util.NewContextualError(
				fmt.Sprintf("entry %v in dns.nameservers is not an IP address", i+1),
				m{"addr": rawAddr},
				err,
			))
			continue
		}
		if addr.Zone() != "" {
			errs = append(errs, fmt.Errorf("entry %v in dns.nameservers is zone-scoped, which is not supported: %s", i+1, rawAddr))
			continue
		}
		out = append(out, addr.Unmap())
	}

	if len(errs) > 0 {
		return nil, joinDNSErrors(errs...)
	}

	return out, nil
}

// parseDNSDomains reads a list of domain suffixes at key k. Entries are handed
// to dnsconfig as written: it compares and publishes them case-insensitively
// and with or without the trailing dot.
func parseDNSDomains(c *config.C, k string) ([]string, error) {
	// Strict because no match domains is the explicit opt in to catch-all DNS:
	// GetStringSlice would read "match_domains: mesh.example.com", a one entry
	// list missing its dash, as no match domains at all and silently point
	// every query on the host at dns.nameservers.
	raw, err := c.GetStringSliceStrict(k)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}

	var errs []error
	for i, domain := range raw {
		switch domain {
		case "":
			errs = append(errs, fmt.Errorf("entry %v in %s is empty", i+1, k))
		case ".":
			// Don't allow '.'. If the user wants to take over everything, they should
			// explicitly configure no match_domains.
			errs = append(errs, fmt.Errorf(`entry %v in %s is the root domain; set "match_domains: []" to send every query to dns.nameservers`, i+1, k))
		}
	}

	if len(errs) > 0 {
		return nil, joinDNSErrors(errs...)
	}

	return raw, nil
}

// parseDNSDomainLists reads dns.search_domains and dns.match_domains. We read
// them together so we can properly handle the fallback behavior when search_domains
// is specified but match_domains is not.
func parseDNSDomainLists(c *config.C) (search, match []string, err error) {
	var errs []error

	search, err = parseDNSDomains(c, "dns.search_domains")
	if err != nil {
		errs = append(errs, err)
	}

	switch {
	case c.IsSet("dns.match_domains"):
		match, err = parseDNSDomains(c, "dns.match_domains")
		if err != nil {
			errs = append(errs, err)
		}

	case len(errs) > 0:
		// search_domains is what needs fixing; say nothing else about it.

	case len(search) == 0:
		errs = append(errs, errors.New(`dns requires search_domains or match_domains; set "match_domains: []" to send every query to dns.nameservers`))

	default:
		match = slices.Clone(search)
	}

	return search, match, joinDNSErrors(errs...)
}

// parseDNSIdentity loads the identity we use for tracking our changes to the local
// resolver configuration. This value is used to disambiguate changes from other
// users of the dnsconfig library, and to recover original OS state in the event
// of an unclean shutdown.
func parseDNSIdentity(c *config.C) (string, error) {
	identity := c.GetString("dns.identity", defaultHostDNSIdentity)
	if err := dnsconfig.ValidateIdentity(identity); err != nil {
		return "", fmt.Errorf("dns.identity is not usable: %w", err)
	}
	return identity, nil
}

// Load dns.marker_path, indicating which path we should use to track whether we've
// made changes or not. Empty (the default) means no marker.
func parseDNSMarkerPath(c *config.C) (string, error) {
	path := c.GetString("dns.marker_path", "")
	if path == "" {
		return "", nil
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("dns.marker_path must be an absolute path: %s", path)
	}
	return path, nil
}

// hostDNSOptions configures a hostDNSController.
type hostDNSOptions struct {
	Logger *slog.Logger

	// Identity scopes this instance's DNS artifacts, cleanup, and the
	// cross-process lock inside dnsconfig. It must be stable across restarts
	// and distinct for every process on the host that manages DNS.
	Identity string

	// MarkerPath is a file that exists from the first Apply until a Close
	// confirms this identity's config is gone. Its presence at startup means
	// a previous instance may have left host DNS config behind. Empty means
	// no marker, and so no crash recovery.
	MarkerPath string
}

// dnsManager is the slice of *dnsconfig.Manager the controller drives; it's an
// interface so tests can exercise the lifecycle without real backends.
type dnsManager interface {
	Set(cfg dnsconfig.Config) error
	Clear() error
	Close() error
	Status() dnsconfig.Status
}

// hostDNSController records host DNS goals with dnsconfig, which is responsible
// for installing, retrying, etc.
type hostDNSController struct {
	opts   hostDNSOptions
	logger *slog.Logger
	// newManager is for testing; nil means dnsconfig.New.
	newManager func(dnsconfig.Options) (dnsManager, error)

	// mu serializes Apply and Deactivate with a Close from the shutdown
	// path, which may run on another goroutine.
	mu sync.Mutex
	// closed makes Close terminal: a caller still finishing a reload must
	// not reinstall DNS that Close already removed.
	closed bool

	// mgr is constructed lazily on the first call that needs it, so hosts
	// that don't use the feature never touch dnsconfig. mgrIface is the
	// interface it was built with.
	mgr         dnsManager
	mgrIface    string
	unsupported bool
}

// hostDNSShutdownTimeout bounds dnsconfig's cleanup in Close, including the
// wait for its host-wide lock. The supervisor's stop timeout must cover it.
const hostDNSShutdownTimeout = 5 * time.Second

// Construct a hostDNSController, but don't wire it up to anything.
func newHostDNSController(o hostDNSOptions) *hostDNSController {
	logger := o.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &hostDNSController{opts: o, logger: logger}
}

// Apply makes desired the host DNS goal; the zero Config is a Deactivate.
// tunDev is the Nebula tun device.
//
// retry reports that the goal was discarded because we couldn't build a manager.
func (c *hostDNSController) Apply(desired dnsconfig.Config, tunDev string) (retry bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	if desired.IsZero() {
		return c.deactivate()
	}
	if !c.ensureManager(tunDev) {
		return !c.unsupported
	}
	if st := c.mgr.Status(); st.Goal == dnsconfig.GoalSet && st.Desired.Equal(desired) {
		return false
	}

	// Written before Set because dnsconfig's worker may write to the host as
	// soon as the goal is recorded.
	wrote := c.writeMarker()
	if err := c.mgr.Set(desired); err != nil {
		c.logger.Error("failed to apply host DNS config", "error", err)
		// If set failed, and we don't own the cleanup, remove our marker because
		// there's actually nothing to do.
		if wrote && !owesCleanup(c.mgr.Status()) {
			c.removeMarker()
		}
		return false
	}
	if !desired.IsSplit() {
		c.logger.Info("host DNS config has no match_domains; overriding all host DNS resolution")
	}
	c.logger.Info("host DNS config requested",
		"resolvers", desired.Nameservers, "match_domains", desired.MatchDomains,
		"search_domains", desired.SearchDomains)
	return false
}

// Deactivate makes removing our host DNS config the goal, including anything a
// prior run left behind. Called when the config no longer requests a resolver.
func (c *hostDNSController) Deactivate() (retry bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	return c.deactivate()
}

func (c *hostDNSController) deactivate() (retry bool) {
	// Without a marker there is nothing to revert, and constructing a manager
	// just to clear would touch host DNS on every host at every start.
	if c.mgr == nil && !c.markerExists() {
		return false
	}
	if !c.ensureManager("") {
		return !c.unsupported
	}
	wasSet := c.mgr.Status().Goal == dnsconfig.GoalSet
	if err := c.mgr.Clear(); err != nil {
		c.logger.Error("failed to revert host DNS config", "error", err)
		return false
	}
	if wasSet {
		c.logger.Info("host DNS config removal requested")
	}
	return false
}

// Close removes this identity's host DNS config and releases the identity.
// Later calls, including Apply and Deactivate, do nothing.
func (c *hostDNSController) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.closeManager()
}

// closeManager closes the manager and returns Close's error.
func (c *hostDNSController) closeManager() error {
	if c.mgr == nil {
		return nil
	}
	mgr := c.mgr
	c.mgr, c.mgrIface = nil, ""
	owed := owesCleanup(mgr.Status())
	err := mgr.Close()
	if err != nil {
		c.logger.Warn("failed to revert host DNS config", "error", err)
	} else if owed {
		c.logger.Info("restored the previous host DNS config")
	}
	// Close returns nil without cleaning up for a manager that never had a goal.
	// The only way we can know that we've actually cleaned up (in the event of
	// stale state from a prior run) is to successfully converge on the GoalClear goal
	// (or a completed Close).
	st := mgr.Status()
	if st.LastConvergedCleared && (err == nil || st.Goal == dnsconfig.GoalClear && st.Converged) {
		c.removeMarker()
	}
	return err
}

// owesCleanup reports whether a manager in st may have host DNS config of
// ours to remove.
func owesCleanup(st dnsconfig.Status) bool {
	return st.Goal == dnsconfig.GoalSet || st.Goal == dnsconfig.GoalClear && !st.Converged
}

func (c *hostDNSController) ensureManager(tunDev string) bool {
	if c.unsupported {
		return false
	}
	if c.mgr != nil {
		if tunDev == "" || tunDev == c.mgrIface {
			return true
		}
		// dnsconfig fixes the interface for a manager's life, so a manager
		// built before the tun device was known (a recovery-only Deactivate)
		// or for a since-renamed device is replaced. Closing reverts whatever
		// the old one applied.
		c.closeManager()
	}

	newManager := c.newManager
	if newManager == nil {
		newManager = newDNSConfigManager
	}
	mgr, err := newManager(dnsconfig.Options{
		Identity:        c.opts.Identity,
		Logger:          c.logger,
		InterfaceName:   tunDev,
		ShutdownTimeout: hostDNSShutdownTimeout,
	})
	if errors.Is(err, errHostDNSUnsupported) {
		// Unrecoverable.
		c.logger.Warn("host DNS configuration is not supported on this host; leaving host DNS unmanaged", "reason", err)
		c.unsupported = true
		return false
	}
	if err != nil {
		c.logger.Error("host DNS is unavailable", "error", err)
		return false
	}
	c.mgr, c.mgrIface = mgr, tunDev
	return true
}

var errHostDNSUnsupported = errors.New("no dnsconfig backend for this host")

// hostDNSNewTimeout bounds manager construction, which initializes the backend.
const hostDNSNewTimeout = 5 * time.Second

func newDNSConfigManager(o dnsconfig.Options) (dnsManager, error) {
	if dnsconfig.Detect() == dnsconfig.BackendNoop {
		return nil, fmt.Errorf("%w: %s", errHostDNSUnsupported, runtime.GOOS)
	}
	ctx, cancel := context.WithTimeout(context.Background(), hostDNSNewTimeout)
	defer cancel()
	return dnsconfig.New(ctx, o)
}

// markerExists reports whether a marker is in place: a regular file at
// MarkerPath. Anything else there, such as a link, is not one we wrote and
// does not count; see writeMarker.
func (c *hostDNSController) markerExists() bool {
	if c.opts.MarkerPath == "" {
		return false
	}
	fi, err := os.Lstat(c.opts.MarkerPath)
	return err == nil && fi.Mode().IsRegular()
}

// writeMarker creates the marker if it is missing and reports whether this
// call created it.
//
// The marker is written with root's privileges at an operator-chosen path, so
// we avoid overwriting anything already at the path.
func (c *hostDNSController) writeMarker() bool {
	if c.opts.MarkerPath == "" {
		return false
	}
	f, err := createMarkerFile(c.opts.MarkerPath)
	if errors.Is(err, os.ErrExist) {
		if !c.markerExists() {
			c.logger.Warn("DNS applied marker path is taken by something that is not a marker; crash recovery will not trigger", "path", c.opts.MarkerPath)
		}
		return false
	}
	if err != nil {
		c.logger.Warn("failed to write DNS applied marker; crash recovery will not trigger", "path", c.opts.MarkerPath, "error", err)
		return false
	}
	// The marker is its existence; the content is for whoever finds it.
	if _, err := f.WriteString("applied\n"); err != nil {
		c.logger.Warn("failed to write DNS applied marker contents", "path", c.opts.MarkerPath, "error", err)
	}
	if err := f.Close(); err != nil {
		c.logger.Warn("failed to close DNS applied marker", "path", c.opts.MarkerPath, "error", err)
	}
	return true
}

func (c *hostDNSController) removeMarker() {
	if c.opts.MarkerPath == "" {
		return
	}
	if err := os.Remove(c.opts.MarkerPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		c.logger.Warn("failed to remove DNS applied marker", "path", c.opts.MarkerPath, "error", err)
	}
}

// hostDNSState tracks the hostDNS lifecycle.
type hostDNSState int

const (
	hostDNSNew hostDNSState = iota
	hostDNSStarted
	hostDNSStopped
)

// dnsController is the *hostDNSController hostDNS drives; an interface so
// tests can exercise the reload lifecycle without dnsconfig.
type dnsController interface {
	Apply(desired dnsconfig.Config, tunDev string) (retry bool)
	Deactivate() (retry bool)
	Close()
}

// hostDNS turns the `dns` stanza into goals for a hostDNSController.
//
// Apply and Deactivate record a goal and return at once, so the lifecycle
// never waits on an OS call. Close is the exception: it reverts the host,
// bounded by hostDNSShutdownTimeout.
type hostDNS struct {
	l      *slog.Logger
	device overlay.Device
	// tunDisabled is whether this process runs without a tun device. It is
	// read once at construction: tun.disabled only takes effect on restart,
	// so we don't need to track it through reloads.
	tunDisabled bool

	// newController is a test seam; nil means newHostDNSController.
	newController func(hostDNSOptions) dnsController

	// mu serializes Start, Restore, and the reload callback. It is held
	// across a controller rebuild, which is the one path here that blocks, so
	// a reload landing during a Restore can not reinstall what Restore is
	// removing.
	mu     sync.Mutex
	runCfg *hostDNSConfig
	// state is used to track where we sit relative to dnsController.
	// Start moves it to started, Restore moves it to stopped.
	state hostDNSState

	// ctrl is built on the first converge, which costs nothing: a controller
	// touches dnsconfig only when it has a goal or a marker to act on.
	// ctrlOpts is what it was built from; a reload that moves the identity or
	// marker path builds a new one, since the controller fixes both for its life.
	ctrl     dnsController
	ctrlOpts hostDNSOptions

	// reloads counts the converges reload has kicked off and not yet seen
	// finish, so a test can wait for one rather than race it.
	reloads sync.WaitGroup

	// retry converges again after the controller could not build its
	// manager, which can happen if a backend is still coming up or an old
	// process is still shutting down. retryDelay doubles from retryBase up to
	// hostDNSRetryMax and resets once a goal is registered.
	//
	// retryBase is for testing; zero means hostDNSRetryBase.
	retry      *time.Timer
	retryDelay time.Duration
	retryBase  time.Duration
}

const (
	hostDNSRetryBase = 2 * time.Second
	hostDNSRetryMax  = time.Minute
)

// newHostDNSFromConfig builds a hostDNS and registers a reload callback. The
// callback is registered before the initial config is read, so a SIGHUP can
// later enable, fix, or disable host DNS even if the initial load failed.
//
// An invalid stanza is reported to the caller but is not fatal: the returned
// hostDNS is always usable, with host DNS left disabled until a HUP supplies a
// config that loads. If dns.identity and dns.marker_path loaded, Start still
// recovers stale state that was left behind; otherwise it leaves the host's
// resolver untouched.
func newHostDNSFromConfig(l *slog.Logger, c *config.C, device overlay.Device) (*hostDNS, error) {
	s := &hostDNS{
		l:           l.With("subsystem", "host_dns"),
		device:      device,
		tunDisabled: c.GetBool("tun.disabled", false),
	}

	c.RegisterReloadCallback(func(c *config.C, r *config.Reload) {
		if err := s.reload(c); err != nil {
			util.LogWithContextIfNeeded("Failed to reload host DNS from config", err, s.l)
			r.Failed()
		}
	})

	if err := s.loadConfig(c); err != nil {
		return s, err
	}
	if cfg := s.config(); cfg.enabled {
		s.l.Info("Host DNS configuration is enabled",
			"identity", cfg.Identity,
			"nameservers", cfg.dns.Nameservers,
			"searchDomains", cfg.dns.SearchDomains,
			"matchDomains", cfg.dns.MatchDomains,
			"split", cfg.dns.IsSplit(),
		)
	}
	return s, nil
}

// loadConfig loads hostDNS configuration and makes it the running configuration/
// goal if there were no errors.
func (s *hostDNS) loadConfig(c *config.C) error {
	opts, optsErr := loadIdentityConfig(c)
	opts.Logger = s.l
	goal, goalErr := loadHostDNSGoal(c, s.tunDisabled)
	err := joinDNSErrors(optsErr, goalErr)

	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case err == nil:
		s.runCfg = &hostDNSConfig{hostDNSOptions: opts, hostDNSGoal: goal}
	case s.runCfg == nil && optsErr == nil:
		s.runCfg = &hostDNSConfig{hostDNSOptions: opts}
	}
	return err
}

// reload loads the configuration a HUP delivered and states its goal.
func (s *hostDNS) reload(c *config.C) error {
	if err := s.loadConfig(c); err != nil {
		return err
	}
	s.reloads.Go(s.converge)
	return nil
}

// Start latches that the tun device is active and registers the goal. Control
// calls it once, after activating the device; this is what Control.hostDNSStart
// points at.
//
// The latch is the whole reason this is separate from converge: nebula arms
// SIGHUP before Control activates the device, so a reload landing in that
// window would otherwise build a Manager against a link that is not up yet. A
// reload that early only loads its configuration, which is applied here.
func (s *hostDNS) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == hostDNSNew {
		// Only move to started from new... Control starts before it stops, but a
		// Restore that beat us here has already declared the host off limits.
		s.state = hostDNSStarted
	}

	s.convergeLocked()
}

// converge registers the goal the configuration asks for and returns. It builds
// the controller if there is none or if the configuration needs a different
// one.
//
// Safe to call when host DNS is disabled, and when nothing was ever applied.
// It no-ops until Start has latched the tun device as active.
func (s *hostDNS) converge() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.convergeLocked()
}

func (s *hostDNS) convergeLocked() {
	if s.state != hostDNSStarted || s.runCfg == nil {
		return
	}
	cfg := *s.runCfg

	ctrl := s.ensureControllerLocked(cfg.hostDNSOptions)
	var retry bool
	if cfg.enabled {
		retry = ctrl.Apply(cfg.dns, s.ifaceName())
	} else {
		// Deactivate rather than Close: this is reversible, so the controller
		// stays live for the reload that turns host DNS back on. It is also
		// how a start with the stanza off recovers what a crash left behind.
		retry = ctrl.Deactivate()
	}
	s.scheduleRetryLocked(retry)
}

// scheduleRetryLocked schedules another converge, or cancels any pending ones,
// as appropriate. At most one is ever pending: Start and reload converge on their
// own and reschedule based on that result.
func (s *hostDNS) scheduleRetryLocked(retry bool) {
	if s.retry != nil {
		s.retry.Stop()
		s.retry = nil
	}
	if !retry {
		s.retryDelay = 0
		return
	}

	base := s.retryBase
	if base == 0 {
		base = hostDNSRetryBase
	}
	switch {
	case s.retryDelay == 0:
		s.retryDelay = base
	case s.retryDelay < hostDNSRetryMax:
		s.retryDelay = min(s.retryDelay*2, hostDNSRetryMax)
	}
	s.l.Info("host DNS will be retried", "in", s.retryDelay)
	// converge takes s.mu and checks the state latch, so a timer that fires
	// after Restore does nothing even if Stop was too late to catch it.
	s.retry = time.AfterFunc(s.retryDelay, s.converge)
}

// Restore puts the host's previous DNS configuration back and releases the
// controller. It is idempotent and safe to call when nothing was ever applied.
func (s *hostDNS) Restore() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = hostDNSStopped
	s.scheduleRetryLocked(false)
	s.closeControllerLocked()
}

// ensureControllerLocked updates s.ctrl to match opts, reusing the existing one
// if there's no change.
func (s *hostDNS) ensureControllerLocked(opts hostDNSOptions) dnsController {
	if s.ctrl != nil {
		if s.ctrlOpts.Identity == opts.Identity && s.ctrlOpts.MarkerPath == opts.MarkerPath {
			return s.ctrl
		}
		s.closeControllerLocked()
	}

	newController := s.newController
	if newController == nil {
		newController = func(o hostDNSOptions) dnsController { return newHostDNSController(o) }
	}
	s.ctrl, s.ctrlOpts = newController(opts), opts
	return s.ctrl
}

// closeControllerLocked takes the controller out of service, reverting
// whatever it applied. It is safe to call with no controller.
func (s *hostDNS) closeControllerLocked() {
	if s.ctrl == nil {
		return
	}
	ctrl := s.ctrl
	s.ctrl, s.ctrlOpts = nil, hostDNSOptions{}
	ctrl.Close()
}

func (s *hostDNS) ifaceName() string {
	if s.device == nil {
		return ""
	}
	return s.device.Name()
}

// config returns the running configuration, or the zero value before one has
// loaded.
func (s *hostDNS) config() hostDNSConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runCfg == nil {
		return hostDNSConfig{}
	}
	return *s.runCfg
}
