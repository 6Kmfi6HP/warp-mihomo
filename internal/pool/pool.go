// Package pool stores WARP identities and renders a two-tier mihomo config:
// a front load-balance pool of direct MASQUE devices, N exit MASQUE devices
// dialing through that front pool, and a TUN that takes the network namespace.
package pool

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
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

	FrontName     = "warp-front"
	FrontPoolName = "warp-front-pool"
	PoolName      = "warp-pool"

	minFronts = 1
	maxFronts = 16
	minExits  = 1
	maxExits  = 16
)

// masquePorts are the TCP/UDP ports Cloudflare WARP MASQUE endpoints listen on.
var masquePorts = []int{443, 500, 1701, 4443, 4500, 8095, 8443}

// Device is one enrolled MASQUE identity plus the anycast address it dials.
type Device struct {
	Role       string `json:"role"`
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

// Ensure loads identities from dir and enrolls only the deficit.
// fronts and exits specify the device counts for the front and exit pools.
// Generations other than the active one are removed: a restart has no live
// sessions, and an uncommitted rotation must not keep its addresses.
// The directory lock must already be held.
func Ensure(dir string, fronts, exits int, reg Registrar) ([]Device, error) {
	if err := validateCounts(fronts, exits); err != nil {
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
	if err := enrollRoleDeficit(dir, &state, gen, RoleFront, fronts, endpoints, reg); err != nil {
		return nil, err
	}
	if err := enrollRoleDeficit(dir, &state, gen, RoleExit, exits, endpoints, reg); err != nil {
		return nil, err
	}
	return selectGeneration(state.Devices, gen, fronts, exits)
}

// Rotate enrolls a new generation on fresh endpoint addresses without making it
// active. The caller activates it only after the generation dials successfully.
// The previous generation stays in the file so its live sessions can finish.
func Rotate(dir string, fronts, exits int, reg Registrar) ([]Device, error) {
	if err := validateCounts(fronts, exits); err != nil {
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
	for range fronts {
		name := nextRoleName(state.Devices, gen, RoleFront)
		id, err := reg(name)
		if err != nil {
			return nil, fmt.Errorf("enroll %s: %w", name, err)
		}
		dev, err := newDevice(RoleFront, name, gen, id, endpoints)
		if err != nil {
			return nil, err
		}
		state.Devices = append(state.Devices, dev)
	}
	for range exits {
		name := nextRoleName(state.Devices, gen, RoleExit)
		id, err := reg(name)
		if err != nil {
			return nil, fmt.Errorf("enroll %s: %w", name, err)
		}
		dev, err := newDevice(RoleExit, name, gen, id, endpoints)
		if err != nil {
			return nil, err
		}
		state.Devices = append(state.Devices, dev)
	}
	if err := save(dir, state); err != nil {
		return nil, err
	}
	return selectGeneration(state.Devices, gen, fronts, exits)
}

func validateCounts(fronts, exits int) error {
	if fronts < minFronts || fronts > maxFronts {
		return fmt.Errorf("fronts must be %d-%d, got %d", minFronts, maxFronts, fronts)
	}
	if exits < minExits || exits > maxExits {
		return fmt.Errorf("exits must be %d-%d, got %d", minExits, maxExits, exits)
	}
	return nil
}

func enrollRoleDeficit(dir string, state *fileState, gen int, role string, want int, endpoints *endpointPool, reg Registrar) error {
	have := countGenerationRole(state.Devices, gen, role)
	for have < want {
		name := nextRoleName(state.Devices, gen, role)
		id, err := reg(name)
		if err != nil {
			return fmt.Errorf("enroll %s: %w", name, err)
		}
		dev, err := newDevice(role, name, gen, id, endpoints)
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

type endpointPool struct {
	octets   map[int]bool
	allPorts map[int]int
	genPorts map[int]int
}

func newEndpointPool(devices []Device, gen int) (*endpointPool, error) {
	octets, err := usedOctets(devices)
	if err != nil {
		return nil, err
	}
	allPorts := make(map[int]int, len(masquePorts))
	genPorts := make(map[int]int, len(masquePorts))
	for _, d := range devices {
		if !slices.Contains(masquePorts, d.Port) {
			continue
		}
		allPorts[d.Port]++
		if d.Generation == gen {
			genPorts[d.Port]++
		}
	}
	return &endpointPool{
		octets:   octets,
		allPorts: allPorts,
		genPorts: genPorts,
	}, nil
}

// pickPort selects a supported MASQUE port, prioritizing ports unused in the
// current generation and then ports unused across all stored generations.
func (p *endpointPool) pickPort() (int, error) {
	bestGen := -1
	bestAll := -1
	var candidates []int
	for _, port := range masquePorts {
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
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
	if err != nil {
		return 0, err
	}
	port := candidates[idx.Int64()]
	p.genPorts[port]++
	p.allPorts[port]++
	return port, nil
}

func newDevice(role, name string, gen int, id warp.Identity, endpoints *endpointPool) (Device, error) {
	if id.PrivateKey == "" || id.PublicKey == "" || id.IP == "" || id.IPv6 == "" {
		return Device{}, fmt.Errorf("enrollment %s returned an empty field", name)
	}
	octet, err := pickOctet(endpoints.octets)
	if err != nil {
		return Device{}, err
	}
	port, err := endpoints.pickPort()
	if err != nil {
		return Device{}, err
	}
	return Device{
		Role:       role,
		Name:       name,
		Generation: gen,
		PrivateKey: id.PrivateKey,
		PublicKey:  id.PublicKey,
		IP:         id.IP,
		IPv6:       id.IPv6,
		Server:     fmt.Sprintf("162.159.198.%d", octet),
		Port:       port,
	}, nil
}

func pickOctet(used map[int]bool) (int, error) {
	var buf [1]byte
	for range 1024 {
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, err
		}
		n := int(buf[0])
		if n < 2 || n == 255 || used[n] {
			continue
		}
		used[n] = true
		return n, nil
	}
	return 0, errors.New("no free WARP endpoint address")
}

func usedOctets(devices []Device) (map[int]bool, error) {
	used := map[int]bool{}
	for _, d := range devices {
		host := strings.TrimPrefix(d.Server, "162.159.198.")
		n, err := strconv.Atoi(host)
		if err != nil || !strings.HasPrefix(d.Server, "162.159.198.") || n < 2 || n > 254 {
			return nil, fmt.Errorf("device %s has bad server %q", d.Name, d.Server)
		}
		if used[n] {
			return nil, fmt.Errorf("duplicate endpoint octet %d", n)
		}
		used[n] = true
	}
	return used, nil
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

// FrontGroupName returns the generation-scoped front load-balance group name.
func FrontGroupName(gen int) string {
	if gen == 0 {
		return FrontPoolName
	}
	return fmt.Sprintf("%s-g%d", FrontPoolName, gen)
}

func rolePrefix(role string, gen int) string {
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

func countGenerationRole(devices []Device, gen int, role string) int {
	n := 0
	for _, d := range devices {
		if d.Generation == gen && d.Role == role {
			n++
		}
	}
	return n
}

func nextRoleName(devices []Device, gen int, role string) string {
	prefix := rolePrefix(role, gen)
	legacy := ""
	if role == RoleFront {
		legacy = legacyFrontName(gen)
	}
	max := 0
	for _, d := range devices {
		if d.Generation != gen || d.Role != role {
			continue
		}
		if legacy != "" && d.Name == legacy && max < 1 {
			max = 1
			continue
		}
		n, ok := deviceIndex(d.Name, prefix)
		if ok && n > max {
			max = n
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

func sortRoleDevices(devs []Device, prefix string) {
	sort.Slice(devs, func(i, j int) bool {
		ni, oki := deviceIndex(devs[i].Name, prefix)
		nj, okj := deviceIndex(devs[j].Name, prefix)
		if oki && okj && ni != nj {
			return ni < nj
		}
		return devs[i].Name < devs[j].Name
	})
}

// SplitRoles separates a generation's devices into fronts and exits and verifies
// they share a single generation with at least one front and one exit.
func SplitRoles(devices []Device) (fronts, exits []Device, gen int, err error) {
	if len(devices) < 2 {
		return nil, nil, 0, fmt.Errorf("yaml wants at least one front and one exit")
	}
	gen = devices[0].Generation
	for _, d := range devices {
		if d.Generation != gen {
			return nil, nil, 0, fmt.Errorf("device %s generation %d does not match %d", d.Name, d.Generation, gen)
		}
		switch d.Role {
		case RoleFront:
			fronts = append(fronts, d)
		case RoleExit:
			exits = append(exits, d)
		default:
			return nil, nil, 0, fmt.Errorf("device %s has unknown role %q", d.Name, d.Role)
		}
	}
	if len(fronts) == 0 {
		return nil, nil, 0, fmt.Errorf("generation %d has no front", gen)
	}
	if len(exits) == 0 {
		return nil, nil, 0, fmt.Errorf("generation %d has no exit", gen)
	}
	return fronts, exits, gen, nil
}

func selectGeneration(devices []Device, gen, wantFronts, wantExits int) ([]Device, error) {
	var fronts []Device
	var exits []Device
	for _, d := range devices {
		if d.Generation != gen {
			continue
		}
		switch d.Role {
		case RoleFront:
			fronts = append(fronts, d)
		case RoleExit:
			exits = append(exits, d)
		default:
			return nil, fmt.Errorf("device %s has unknown role %q", d.Name, d.Role)
		}
	}
	sortRoleDevices(fronts, rolePrefix(RoleFront, gen))
	sortRoleDevices(exits, rolePrefix(RoleExit, gen))
	if len(fronts) < wantFronts {
		return nil, fmt.Errorf("generation %d has %d fronts, want %d", gen, len(fronts), wantFronts)
	}
	if len(exits) < wantExits {
		return nil, fmt.Errorf("generation %d has %d exits, want %d", gen, len(exits), wantExits)
	}
	selected := make([]Device, 0, wantFronts+wantExits)
	selected = append(selected, fronts[:wantFronts]...)
	selected = append(selected, exits[:wantExits]...)
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
