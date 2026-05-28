package vssd

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
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
	return os.WriteFile(path, newData, 0600)
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
