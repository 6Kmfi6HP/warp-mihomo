// Package pool stores WARP identities and renders a dual-protocol mihomo config:
// dedicated H3 (QUIC+BBR) and H2 front load-balance pools, matching H3/H2 exit
// devices dialing through their respective front pool, and one unified
// warp-pool load-balancing across all H3 and H2 exits behind a TUN.
package pool

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"warp-mihomo/internal/warp"
)

const (
	RoleFront = "front"
	RoleExit  = "exit"

	NetworkH2 = "h2"
	NetworkH3 = "h3"

	FrontName       = "warp-front"
	FrontPoolName   = "warp-front-pool"
	FrontH3PoolName = "warp-front-h3-pool"
	FrontH2PoolName = "warp-front-h2-pool"
	PoolName        = "warp-pool"

	maxTrackFronts = 16
	maxTrackExits  = 16
	maxH3PerGen    = 7 // 2 H3 IPs * 7 ports = 14 endpoints across active + retiring gen
)

// masquePorts are the TCP/UDP ports Cloudflare WARP MASQUE endpoints listen on.
// Non-443 ports are listed first so H3 fronts avoid occasional 443 slow handshakes
// before falling back to 443.
var masquePorts = []int{4443, 8443, 500, 1701, 4500, 8095, 443}

// h3Octets are the Cloudflare WARP anycast IPv4 octets confirmed to serve H3/QUIC.
var h3Octets = []int{1, 2}

// Spec describes how many front and exit devices to maintain on each protocol track.
type Spec struct {
	FrontsH3 int
	ExitsH3  int
	FrontsH2 int
	ExitsH2  int
}

// Plan separates a single generation's devices by protocol track and role.
type Plan struct {
	Gen      int
	FrontsH3 []Device
	ExitsH3  []Device
	FrontsH2 []Device
	ExitsH2  []Device
}

// Device is one enrolled MASQUE identity plus the anycast address it dials.
type Device struct {
	Role       string `json:"role"`
	Network    string `json:"network,omitempty"`
	Name       string `json:"name"`
	Generation int    `json:"generation,omitempty"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	IP         string `json:"ip"`
	IPv6       string `json:"ipv6"`
	Server     string `json:"server"`
	Port       int    `json:"port"`
}

// Registrar enrolls one new device. name is the Cloudflare device name.
type Registrar func(name string) (warp.Identity, error)

type fileState struct {
	Devices          []Device `json:"devices"`
	ActiveGeneration *int     `json:"activeGeneration,omitempty"`
}

// Lock holds the state directory so two processes cannot enroll or run at once.
// The caller keeps it until the process exits.
func Lock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "devices.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another warp-mihomo holds %s: %w", dir, err)
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// Ensure loads identities from dir and enrolls only the deficit per track and role.
// Generations other than the active one are removed: a restart has no live
// sessions, and an uncommitted rotation must not keep its addresses.
// The directory lock must already be held.
func Ensure(dir string, spec Spec, reg Registrar) ([]Device, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}
	state, err := load(dir)
	if err != nil {
		return nil, err
	}
	gen := activeGeneration(state)
	kept := make([]Device, 0, len(state.Devices))
	dropped := false
	for _, dev := range state.Devices {
		if dev.Generation == gen {
			kept = append(kept, dev)
			continue
		}
		dropped = true
	}
	if dropped {
		state.Devices = kept
		if err := save(dir, state); err != nil {
			return nil, err
		}
	}
	endpoints, err := newEndpointPool(state.Devices, gen)
	if err != nil {
		return nil, err
	}
	targets := []struct {
		role string
		net  string
		want int
	}{
		{RoleFront, NetworkH3, spec.FrontsH3},
		{RoleExit, NetworkH3, spec.ExitsH3},
		{RoleFront, NetworkH2, spec.FrontsH2},
		{RoleExit, NetworkH2, spec.ExitsH2},
	}
	for _, t := range targets {
		if err := enrollTrackDeficit(dir, &state, gen, t.role, t.net, t.want, endpoints, reg); err != nil {
			return nil, err
		}
	}
	return selectGeneration(state.Devices, gen, spec)
}

// Rotate enrolls a new generation on fresh endpoint addresses without making it
// active. The caller activates it only after the generation dials successfully.
// The previous generation stays in the file so its live sessions can finish.
func Rotate(dir string, spec Spec, reg Registrar) ([]Device, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}
	state, err := load(dir)
	if err != nil {
		return nil, err
	}
	gen := maxGeneration(state.Devices) + 1
	endpoints, err := newEndpointPool(state.Devices, gen)
	if err != nil {
		return nil, err
	}
	targets := []struct {
		role string
		net  string
		want int
	}{
		{RoleFront, NetworkH3, spec.FrontsH3},
		{RoleFront, NetworkH2, spec.FrontsH2},
		{RoleExit, NetworkH3, spec.ExitsH3},
		{RoleExit, NetworkH2, spec.ExitsH2},
	}
	for _, t := range targets {
		for range t.want {
			name := nextRoleName(state.Devices, gen, t.role, t.net)
			id, err := reg(name)
			if err != nil {
				return nil, fmt.Errorf("enroll %s: %w", name, err)
			}
			dev, err := newDevice(t.role, t.net, name, gen, id, endpoints)
			if err != nil {
				return nil, err
			}
			state.Devices = append(state.Devices, dev)
		}
	}
	if err := save(dir, state); err != nil {
		return nil, err
	}
	return selectGeneration(state.Devices, gen, spec)
}

func (s Spec) validate() error {
	if err := validateTrack("h3", s.FrontsH3, s.ExitsH3); err != nil {
		return err
	}
	if err := validateTrack("h2", s.FrontsH2, s.ExitsH2); err != nil {
		return err
	}
	if s.FrontsH3+s.ExitsH3 > maxH3PerGen {
		return fmt.Errorf("h3 fronts+exits must be <= %d so active and rotating generations fit %d H3 endpoints, got %d", maxH3PerGen, len(h3Octets)*len(masquePorts), s.FrontsH3+s.ExitsH3)
	}
	if s.ExitsH3+s.ExitsH2 == 0 {
		return errors.New("at least one protocol track (h3 or h2) must be enabled")
	}
	return nil
}

func validateTrack(label string, fronts, exits int) error {
	if fronts < 0 || fronts > maxTrackFronts {
		return fmt.Errorf("%s fronts must be 0-%d, got %d", label, maxTrackFronts, fronts)
	}
	if exits < 0 || exits > maxTrackExits {
		return fmt.Errorf("%s exits must be 0-%d, got %d", label, maxTrackExits, exits)
	}
	if (fronts == 0) != (exits == 0) {
		return fmt.Errorf("%s fronts (%d) and exits (%d) must both be 0 or both >= 1", label, fronts, exits)
	}
	return nil
}

func enrollTrackDeficit(dir string, state *fileState, gen int, role, network string, want int, endpoints *endpointPool, reg Registrar) error {
	have := countGenerationRoleNetwork(state.Devices, gen, role, network)
	for have < want {
		name := nextRoleName(state.Devices, gen, role, network)
		id, err := reg(name)
		if err != nil {
			return fmt.Errorf("enroll %s: %w", name, err)
		}
		dev, err := newDevice(role, network, name, gen, id, endpoints)
		if err != nil {
			return err
		}
		state.Devices = append(state.Devices, dev)
		if err := save(dir, *state); err != nil {
			return err
		}
		have++
	}
	return nil
}

type endpointKey struct {
	octet int
	port  int
}

type endpointPool struct {
	h2Octets map[int]bool
	usedPair map[endpointKey]bool
	allPorts map[int]int
	genPorts map[int]int
}

func newEndpointPool(devices []Device, gen int) (*endpointPool, error) {
	h2Octets := map[int]bool{}
	usedPair := map[endpointKey]bool{}
	allPorts := make(map[int]int, len(masquePorts))
	genPorts := make(map[int]int, len(masquePorts))

	for _, d := range devices {
		octet, err := parseWarpOctet(d)
		if err != nil {
			return nil, err
		}
		pair := endpointKey{octet: octet, port: d.Port}
		if usedPair[pair] {
			return nil, fmt.Errorf("duplicate endpoint 162.159.198.%d:%d", octet, d.Port)
		}
		usedPair[pair] = true

		if deviceNetwork(d) == NetworkH2 {
			if h2Octets[octet] {
				return nil, fmt.Errorf("duplicate h2 endpoint octet %d", octet)
			}
			h2Octets[octet] = true
		}

		if slices.Contains(masquePorts, d.Port) {
			allPorts[d.Port]++
			if d.Generation == gen {
				genPorts[d.Port]++
			}
		}
	}
	return &endpointPool{
		h2Octets: h2Octets,
		usedPair: usedPair,
		allPorts: allPorts,
		genPorts: genPorts,
	}, nil
}

func parseWarpOctet(d Device) (int, error) {
	host := strings.TrimPrefix(d.Server, "162.159.198.")
	n, err := strconv.Atoi(host)
	if err != nil || !strings.HasPrefix(d.Server, "162.159.198.") || n < 1 || n > 254 {
		return 0, fmt.Errorf("device %s has bad server %q", d.Name, d.Server)
	}
	if deviceNetwork(d) == NetworkH3 && !slices.Contains(h3Octets, n) {
		return 0, fmt.Errorf("h3 device %s has unsupported server %q", d.Name, d.Server)
	}
	return n, nil
}

// pickPort selects a supported MASQUE port, prioritizing ports unused in the
// current generation and then ports unused across all stored generations.
func (p *endpointPool) pickPort(allowed []int, deterministic bool) (int, error) {
	bestGen := -1
	bestAll := -1
	var candidates []int
	for _, port := range allowed {
		gc := p.genPorts[port]
		ac := p.allPorts[port]
		if bestGen == -1 || gc < bestGen || (gc == bestGen && ac < bestAll) {
			bestGen = gc
			bestAll = ac
			candidates = append(candidates[:0], port)
		} else if gc == bestGen && ac == bestAll {
			candidates = append(candidates, port)
		}
	}
	if len(candidates) == 0 {
		return 0, errors.New("no available MASQUE port")
	}
	var port int
	if deterministic {
		port = candidates[0]
	} else {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
		if err != nil {
			return 0, err
		}
		port = candidates[idx.Int64()]
	}
	p.genPorts[port]++
	p.allPorts[port]++
	return port, nil
}

// pickH3Endpoint assigns a unique (162.159.198.1/.2, port) pair for H3 devices.
// Ports are balanced across the generation and across stored generations.
func (p *endpointPool) pickH3Endpoint() (string, int, error) {
	var bestOctet int
	var allowedPorts []int
	bestUsed := len(masquePorts) + 1
	for _, octet := range h3Octets {
		var free []int
		for _, port := range masquePorts {
			if !p.usedPair[endpointKey{octet: octet, port: port}] {
				free = append(free, port)
			}
		}
		usedCount := len(masquePorts) - len(free)
		if len(free) > 0 && usedCount < bestUsed {
			bestUsed = usedCount
			bestOctet = octet
			allowedPorts = free
		}
	}
	if len(allowedPorts) == 0 {
		return "", 0, errors.New("no free H3 WARP endpoint address:port")
	}
	port, err := p.pickPort(allowedPorts, true)
	if err != nil {
		return "", 0, err
	}
	p.usedPair[endpointKey{octet: bestOctet, port: port}] = true
	return fmt.Sprintf("162.159.198.%d", bestOctet), port, nil
}

// pickH2Endpoint assigns a unique 162.159.198.3..254 IP and balanced port for H2.
func (p *endpointPool) pickH2Endpoint() (string, int, error) {
	octet, err := pickH2Octet(p.h2Octets)
	if err != nil {
		return "", 0, err
	}
	var free []int
	for _, port := range masquePorts {
		if !p.usedPair[endpointKey{octet: octet, port: port}] {
			free = append(free, port)
		}
	}
	port, err := p.pickPort(free, false)
	if err != nil {
		return "", 0, err
	}
	p.usedPair[endpointKey{octet: octet, port: port}] = true
	return fmt.Sprintf("162.159.198.%d", octet), port, nil
}

func newDevice(role, network, name string, gen int, id warp.Identity, endpoints *endpointPool) (Device, error) {
	if id.PrivateKey == "" || id.PublicKey == "" || id.IP == "" || id.IPv6 == "" {
		return Device{}, fmt.Errorf("enrollment %s returned an empty field", name)
	}
	var server string
	var port int
	var err error
	switch network {
	case NetworkH3:
		server, port, err = endpoints.pickH3Endpoint()
	case NetworkH2:
		server, port, err = endpoints.pickH2Endpoint()
	default:
		return Device{}, fmt.Errorf("unsupported network %q", network)
	}
	if err != nil {
		return Device{}, err
	}
	return Device{
		Role:       role,
		Network:    network,
		Name:       name,
		Generation: gen,
		PrivateKey: id.PrivateKey,
		PublicKey:  id.PublicKey,
		IP:         id.IP,
		IPv6:       id.IPv6,
		Server:     server,
		Port:       port,
	}, nil
}

func pickH2Octet(used map[int]bool) (int, error) {
	var buf [1]byte
	for range 1024 {
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, err
		}
		n := int(buf[0])
		if n < 3 || n == 255 || used[n] {
			continue
		}
		used[n] = true
		return n, nil
	}
	return 0, errors.New("no free H2 WARP endpoint address")
}

func deviceNetwork(d Device) string {
	if d.Network == "" {
		return NetworkH2
	}
	return d.Network
}

func activeGeneration(state fileState) int {
	if state.ActiveGeneration == nil {
		return 0
	}
	return *state.ActiveGeneration
}

func maxGeneration(devices []Device) int {
	max := 0
	for _, d := range devices {
		if d.Generation > max {
			max = d.Generation
		}
	}
	return max
}

// FrontGroupName returns the generation-scoped front load-balance group name
// for the given protocol track ("h3" or "h2").
func FrontGroupName(network string, gen int) string {
	base := FrontH2PoolName
	if network == NetworkH3 {
		base = FrontH3PoolName
	}
	if gen == 0 {
		return base
	}
	return fmt.Sprintf("%s-g%d", base, gen)
}

func rolePrefix(role, network string, gen int) string {
	base := "warp-" + role + "-" + network
	if gen == 0 {
		return base + "-"
	}
	return fmt.Sprintf("%s-g%d-", base, gen)
}

func legacyRolePrefix(role string, gen int) string {
	base := "warp-" + role
	if gen == 0 {
		return base + "-"
	}
	return fmt.Sprintf("%s-g%d-", base, gen)
}

func legacyFrontName(gen int) string {
	if gen == 0 {
		return FrontName
	}
	return fmt.Sprintf("warp-front-g%d", gen)
}

func countGenerationRoleNetwork(devices []Device, gen int, role, network string) int {
	n := 0
	for _, d := range devices {
		if d.Generation == gen && d.Role == role && deviceNetwork(d) == network {
			n++
		}
	}
	return n
}

func nextRoleName(devices []Device, gen int, role, network string) string {
	prefix := rolePrefix(role, network, gen)
	legacyPrefix := ""
	legacySingle := ""
	if network == NetworkH2 {
		legacyPrefix = legacyRolePrefix(role, gen)
		if role == RoleFront {
			legacySingle = legacyFrontName(gen)
		}
	}
	max := 0
	for _, d := range devices {
		if d.Generation != gen || d.Role != role || deviceNetwork(d) != network {
			continue
		}
		if legacySingle != "" && d.Name == legacySingle && max < 1 {
			max = 1
			continue
		}
		if n, ok := deviceIndex(d.Name, prefix); ok && n > max {
			max = n
			continue
		}
		if legacyPrefix != "" {
			if n, ok := deviceIndex(d.Name, legacyPrefix); ok && n > max {
				max = n
			}
		}
	}
	return prefix + strconv.Itoa(max+1)
}

func deviceIndex(name, prefix string) (int, bool) {
	if !strings.HasPrefix(name, prefix) {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(name, prefix))
	if err != nil {
		return 0, false
	}
	return n, true
}

func sortTrackDevices(devs []Device, role, network string, gen int) {
	prefix := rolePrefix(role, network, gen)
	legacyPrefix := ""
	if network == NetworkH2 {
		legacyPrefix = legacyRolePrefix(role, gen)
	}
	indexOf := func(name string) (int, bool) {
		if n, ok := deviceIndex(name, prefix); ok {
			return n, true
		}
		if legacyPrefix != "" {
			return deviceIndex(name, legacyPrefix)
		}
		return 0, false
	}
	sort.Slice(devs, func(i, j int) bool {
		ni, oki := indexOf(devs[i].Name)
		nj, okj := indexOf(devs[j].Name)
		if oki && okj && ni != nj {
			return ni < nj
		}
		return devs[i].Name < devs[j].Name
	})
}

// Fronts returns all front devices across both tracks (H3 first, then H2).
func (p Plan) Fronts() []Device {
	out := make([]Device, 0, len(p.FrontsH3)+len(p.FrontsH2))
	out = append(out, p.FrontsH3...)
	out = append(out, p.FrontsH2...)
	return out
}

// Exits returns all exit devices across both tracks (H3 first, then H2).
func (p Plan) Exits() []Device {
	out := make([]Device, 0, len(p.ExitsH3)+len(p.ExitsH2))
	out = append(out, p.ExitsH3...)
	out = append(out, p.ExitsH2...)
	return out
}

// FrontGroupNames returns the generation-scoped front pool names present in the plan.
func (p Plan) FrontGroupNames() []string {
	var names []string
	if len(p.FrontsH3) > 0 {
		names = append(names, FrontGroupName(NetworkH3, p.Gen))
	}
	if len(p.FrontsH2) > 0 {
		names = append(names, FrontGroupName(NetworkH2, p.Gen))
	}
	return names
}

// SplitPlan groups a single generation's devices by protocol track and role and
// verifies every enabled track has at least one front and one exit.
func SplitPlan(devices []Device) (Plan, error) {
	if len(devices) < 2 {
		return Plan{}, fmt.Errorf("yaml wants at least one front and one exit")
	}
	plan := Plan{Gen: devices[0].Generation}
	for _, d := range devices {
		if d.Generation != plan.Gen {
			return Plan{}, fmt.Errorf("device %s generation %d does not match %d", d.Name, d.Generation, plan.Gen)
		}
		net := deviceNetwork(d)
		if net != NetworkH3 && net != NetworkH2 {
			return Plan{}, fmt.Errorf("device %s has unknown network %q", d.Name, d.Network)
		}
		switch d.Role {
		case RoleFront:
			if net == NetworkH3 {
				plan.FrontsH3 = append(plan.FrontsH3, d)
			} else {
				plan.FrontsH2 = append(plan.FrontsH2, d)
			}
		case RoleExit:
			if net == NetworkH3 {
				plan.ExitsH3 = append(plan.ExitsH3, d)
			} else {
				plan.ExitsH2 = append(plan.ExitsH2, d)
			}
		default:
			return Plan{}, fmt.Errorf("device %s has unknown role %q", d.Name, d.Role)
		}
	}
	if (len(plan.FrontsH3) == 0) != (len(plan.ExitsH3) == 0) {
		return Plan{}, fmt.Errorf("generation %d h3 track has %d fronts and %d exits", plan.Gen, len(plan.FrontsH3), len(plan.ExitsH3))
	}
	if (len(plan.FrontsH2) == 0) != (len(plan.ExitsH2) == 0) {
		return Plan{}, fmt.Errorf("generation %d h2 track has %d fronts and %d exits", plan.Gen, len(plan.FrontsH2), len(plan.ExitsH2))
	}
	if len(plan.ExitsH3)+len(plan.ExitsH2) == 0 {
		return Plan{}, fmt.Errorf("generation %d has no exit", plan.Gen)
	}
	return plan, nil
}

func selectGeneration(devices []Device, gen int, spec Spec) ([]Device, error) {
	var frontsH3, exitsH3, frontsH2, exitsH2 []Device
	for _, d := range devices {
		if d.Generation != gen {
			continue
		}
		net := deviceNetwork(d)
		switch d.Role {
		case RoleFront:
			if net == NetworkH3 {
				frontsH3 = append(frontsH3, d)
			} else {
				frontsH2 = append(frontsH2, d)
			}
		case RoleExit:
			if net == NetworkH3 {
				exitsH3 = append(exitsH3, d)
			} else {
				exitsH2 = append(exitsH2, d)
			}
		default:
			return nil, fmt.Errorf("device %s has unknown role %q", d.Name, d.Role)
		}
	}
	sortTrackDevices(frontsH3, RoleFront, NetworkH3, gen)
	sortTrackDevices(exitsH3, RoleExit, NetworkH3, gen)
	sortTrackDevices(frontsH2, RoleFront, NetworkH2, gen)
	sortTrackDevices(exitsH2, RoleExit, NetworkH2, gen)

	if len(frontsH3) < spec.FrontsH3 {
		return nil, fmt.Errorf("generation %d has %d h3 fronts, want %d", gen, len(frontsH3), spec.FrontsH3)
	}
	if len(exitsH3) < spec.ExitsH3 {
		return nil, fmt.Errorf("generation %d has %d h3 exits, want %d", gen, len(exitsH3), spec.ExitsH3)
	}
	if len(frontsH2) < spec.FrontsH2 {
		return nil, fmt.Errorf("generation %d has %d h2 fronts, want %d", gen, len(frontsH2), spec.FrontsH2)
	}
	if len(exitsH2) < spec.ExitsH2 {
		return nil, fmt.Errorf("generation %d has %d h2 exits, want %d", gen, len(exitsH2), spec.ExitsH2)
	}

	selected := make([]Device, 0, spec.FrontsH3+spec.ExitsH3+spec.FrontsH2+spec.ExitsH2)
	selected = append(selected, frontsH3[:spec.FrontsH3]...)
	selected = append(selected, frontsH2[:spec.FrontsH2]...)
	selected = append(selected, exitsH3[:spec.ExitsH3]...)
	selected = append(selected, exitsH2[:spec.ExitsH2]...)
	return selected, nil
}

// GenerationIdle reports whether none of the names appear in live connection chains.
// Pass the generation's exit names. A front-only chain is the exit transport, not
// a consumer, and must not keep the generation alive. An exit is busy while any
// consumer chain names it; its front stays up until those exits are closed.
func GenerationIdle(names []string, chains [][]string) bool {
	busy := map[string]struct{}{}
	for _, chain := range chains {
		for _, name := range chain {
			busy[name] = struct{}{}
		}
	}
	for _, name := range names {
		if _, ok := busy[name]; ok {
			return false
		}
	}
	return true
}

func ForgetGeneration(dir string, gen int) error {
	state, err := load(dir)
	if err != nil {
		return err
	}
	if activeGeneration(state) == gen {
		return fmt.Errorf("refusing to forget the active generation %d", gen)
	}
	kept := make([]Device, 0, len(state.Devices))
	for _, d := range state.Devices {
		if d.Generation != gen {
			kept = append(kept, d)
		}
	}
	state.Devices = kept
	return save(dir, state)
}

func statePath(dir string) string {
	return filepath.Join(dir, "devices.json")
}

func load(dir string) (fileState, error) {
	raw, err := os.ReadFile(statePath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return fileState{}, nil
	}
	if err != nil {
		return fileState{}, err
	}
	var state fileState
	if err := json.Unmarshal(raw, &state); err != nil {
		return fileState{}, fmt.Errorf("devices.json: %w", err)
	}
	for i := range state.Devices {
		if state.Devices[i].Network == "" {
			state.Devices[i].Network = NetworkH2
		}
	}
	return state, nil
}

func Activate(dir string, gen int) error {
	state, err := load(dir)
	if err != nil {
		return err
	}
	state.ActiveGeneration = &gen
	return save(dir, state)
}

func save(dir string, state fileState) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	path := statePath(dir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ValidateAddr parses ip:port for sanity in tests/logging.
func ValidateAddr(server string, port int) error {
	addr, err := netip.ParseAddr(server)
	if err != nil || port <= 0 || port > 65535 || !addr.IsValid() {
		return fmt.Errorf("invalid endpoint %s:%d", server, port)
	}
	return nil
}
