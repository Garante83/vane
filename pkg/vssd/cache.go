package vssd

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// CacheEntry represents an active network service profile.
type CacheEntry struct {
	IP              string    `json:"ip"`
	IPv6            string    `json:"ipv6,omitempty"`
	MAC             string    `json:"mac,omitempty"`
	Vendor          string    `json:"vendor,omitempty"`
	Name            string    `json:"name,omitempty"`
	Ports           []int     `json:"ports,omitempty"`
	DiscoveryMethod string    `json:"discovery_method"`
	LastSeen        time.Time `json:"last_seen"`
}

// InterfaceMap maps semantic token names to their corresponding cache profiles.
type InterfaceMap map[string]CacheEntry

// CacheSchema represents the top-level structure of the cache.json file.
type CacheSchema map[string]InterfaceMap

var cacheMutex sync.RWMutex

// GetCachePath returns the absolute path of the local Vane cache file.
func GetCachePath() (string, error) {
	home := os.Getenv("HOME")
	if home == "" || home == "/root" {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			if _, err := os.Stat("/home/" + sudoUser); err == nil {
				home = "/home/" + sudoUser
			} else if _, err := os.Stat("/Users/" + sudoUser); err == nil {
				home = "/Users/" + sudoUser
			}
		}
	}
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return "", err
		}
	}
	return filepath.Join(home, ".config", "vane", "cache.json"), nil
}

// ResolveFromCache attempts to find a dynamic IP mapping for a given interface and token.
func ResolveFromCache(iface, token string) (string, bool) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	path, err := GetCachePath()
	if err != nil {
		return "", false
	}

	// If the cache file does not exist, return a miss silently
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", false
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}

	var schema CacheSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		return "", false
	}

	ifaceMap, exists := schema[iface]
	if !exists {
		return "", false
	}

	entry, exists := ifaceMap[token]
	if !exists {
		return "", false
	}

	return entry.IP, true
}

// UpdateCache safely stores or updates a service entry inside the cache.json file.
// It strictly guarantees owner-only permissions (chmod 0600) on the folder and file.
func UpdateCache(iface, token string, entry CacheEntry) error {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	path, err := GetCachePath()
	if err != nil {
		return err
	}

	// Ensure the parent configuration directory exists with owner-only permissions (0700)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	schema := make(CacheSchema)
	if _, err := os.Stat(path); err == nil {
		data, readErr := os.ReadFile(path)
		if readErr == nil {
			_ = json.Unmarshal(data, &schema)
		}
	}

	if _, exists := schema[iface]; !exists {
		schema[iface] = make(InterfaceMap)
	}

	entry.LastSeen = time.Now()
	schema[iface][token] = entry

	newData, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return err
	}

	// Write the file strictly with owner-only read/write permissions (0600)
	if err := os.WriteFile(path, newData, 0600); err != nil {
		return err
	}

	// Restore correct user ownership if run under sudo
	EnsureCacheOwnership(path)

	return nil
}

// EnsureCacheOwnership checks if we are running under sudo and safely restores
// correct file and directory ownership to the non-root SUDO_USER.
func EnsureCacheOwnership(path string) {
	if os.Geteuid() != 0 {
		return
	}
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser == "" {
		return
	}
	u, err := user.Lookup(sudoUser)
	if err != nil {
		return
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)

	dir := filepath.Dir(path)
	_ = os.Chown(path, uid, gid)
	_ = os.Chown(dir, uid, gid)
}

// LoadCacheForInterface reads all cached service mappings for a given network interface.
func LoadCacheForInterface(iface string) (InterfaceMap, error) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	path, err := GetCachePath()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return make(InterfaceMap), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var schema CacheSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, err
	}

	ifaceMap, exists := schema[iface]
	if !exists {
		return make(InterfaceMap), nil
	}

	return ifaceMap, nil
}
