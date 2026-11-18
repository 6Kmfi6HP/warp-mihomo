// Package pool stores WARP identities and renders a one-hop mihomo config:
// one direct front, N masque exits that dial through it, and a TUN that
// takes the network namespace.
package pool

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"warp-mihomo/internal/warp"
)

const (
	RoleFront = "front"
	RoleExit  = "exit"

	FrontName = "warp-front"
	PoolName  = "warp-pool"

	minExits   = 1
	maxExits   = 16
	masquePort = 443
)

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
// exits is the number of devices behind the front, not counting the front.
// Generations other than the active one are removed: a restart has no live
// sessions, and an uncommitted rotation must not keep its addresses.
// The directory lock must already be held.
func Ensure(dir string, exits int, reg Registrar) ([]Device, error) {
	if exits < minExits || exits > maxExits {
		return nil, fmt.Errorf("exits must be %d-%d, got %d", minExits, maxExits, exits)
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
	used, err := usedOctets(state.Devices)
	if err != nil {
		return nil, err
	}
	if !hasGenerationRole(state.Devices, gen, RoleFront) {
		id, err := reg(frontName(gen))
		if err != nil {
			return nil, fmt.Errorf("enroll front: %w", err)
		}
		dev, err := newDevice(RoleFront, frontName(gen), gen, id, used)
		if err != nil {
			return nil, err
		}
		state.Devices = append(state.Devices, dev)
		if err := save(dir, state); err != nil {
			return nil, err
		}
	}
	have := countGenerationRole(state.Devices, gen, RoleExit)
	for have < exits {
		name := nextExitName(state.Devices, gen)
		id, err := reg(name)
		if err != nil {
			return nil, fmt.Errorf("enroll %s: %w", name, err)
		}
		dev, err := newDevice(RoleExit, name, gen, id, used)
		if err != nil {
			return nil, err
		}
		state.Devices = append(state.Devices, dev)
		if err := save(dir, state); err != nil {
			return nil, err
		}
		have++
	}
	return selectGeneration(state.Devices, gen, exits)
}

// Rotate enrolls a new generation on fresh endpoint addresses without making it
// active. The caller activates it only after the generation dials successfully.
// The previous generation stays in the file so its live sessions can finish.
func Rotate(dir string, exits int, reg Registrar) ([]Device, error) {
	if exits < minExits || exits > maxExits {
		return nil, fmt.Errorf("exits must be %d-%d, got %d", minExits, maxExits, exits)
	}
	state, err := load(dir)
	if err != nil {
		return nil, err
	}
	gen := maxGeneration(state.Devices) + 1
	used, err := usedOctets(state.Devices)
	if err != nil {
		return nil, err
	}
	id, err := reg(frontName(gen))
	if err != nil {
		return nil, fmt.Errorf("enroll front: %w", err)
	}
	front, err := newDevice(RoleFront, frontName(gen), gen, id, used)
	if err != nil {
		return nil, err
	}
	state.Devices = append(state.Devices, front)
	for range exits {
		name := nextExitName(state.Devices, gen)
		id, err := reg(name)
		if err != nil {
			return nil, fmt.Errorf("enroll %s: %w", name, err)
		}
		dev, err := newDevice(RoleExit, name, gen, id, used)
		if err != nil {
			return nil, err
		}
		state.Devices = append(state.Devices, dev)
	}
	if err := save(dir, state); err != nil {
		return nil, err
	}
	return selectGeneration(state.Devices, gen, exits)
}

func newDevice(role, name string, gen int, id warp.Identity, used map[int]bool) (Device, error) {
	if id.PrivateKey == "" || id.PublicKey == "" || id.IP == "" || id.IPv6 == "" {
		return Device{}, fmt.Errorf("enrollment %s returned an empty field", name)
	}
	octet, err := pickOctet(used)
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
		Port:       masquePort,
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

func frontName(gen int) string {
	if gen == 0 {
		return FrontName
	}
	return fmt.Sprintf("warp-front-g%d", gen)
}

func exitPrefix(gen int) string {
	if gen == 0 {
		return "warp-exit-"
	}
	return fmt.Sprintf("warp-exit-g%d-", gen)
}

func hasGenerationRole(devices []Device, gen int, role string) bool {
	return countGenerationRole(devices, gen, role) > 0
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

func nextExitName(devices []Device, gen int) string {
	prefix := exitPrefix(gen)
	max := 0
	for _, d := range devices {
		if d.Generation != gen || d.Role != RoleExit || !strings.HasPrefix(d.Name, prefix) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(d.Name, prefix))
		if err != nil {
			continue
		}
		if n > max {
			max = n
		}
	}
	return prefix + strconv.Itoa(max+1)
}

func selectGeneration(devices []Device, gen, exits int) ([]Device, error) {
	var front *Device
	var out []Device
	for _, d := range devices {
		if d.Generation != gen {
			continue
		}
		switch d.Role {
		case RoleFront:
			if front != nil {
				return nil, fmt.Errorf("generation %d has more than one front", gen)
			}
			cp := d
			front = &cp
		case RoleExit:
			out = append(out, d)
		default:
			return nil, fmt.Errorf("device %s has unknown role %q", d.Name, d.Role)
		}
	}
	if front == nil {
		return nil, fmt.Errorf("generation %d has no front", gen)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) < exits {
		return nil, fmt.Errorf("generation %d has %d exits, want %d", gen, len(out), exits)
	}
	selected := make([]Device, 0, 1+exits)
	selected = append(selected, *front)
	selected = append(selected, out[:exits]...)
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
