//go:build nosweep
// +build nosweep

package vssd

import (
	"fmt"
	"os"
	"strings"
)

// RunTargetedDiscovery is disabled in the Enterprise friendly build to comply
// with strict corporate security policies regarding unauthorized network sweeps.
func RunTargetedDiscovery(ifaceName string) (map[string]CacheEntry, error) {
	lang := os.Getenv("LANG")
	if strings.HasPrefix(lang, "de") {
		return nil, fmt.Errorf("aktiver Nachbarschafts-Sweep ist in diesem Enterprise-Build von Vane deaktiviert")
	}
	return nil, fmt.Errorf("active neighborhood sweeping is disabled in this Enterprise build of Vane")
}
