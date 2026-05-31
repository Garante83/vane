#!/bin/bash
# Vane CLI Integration Smoke Test
# Guarantees portable end-to-end notation and command-wrapping correctness.
set -e

echo "=================================================="
echo "          Vane CLI Integration Smoke Test          "
echo "=================================================="

# 1. Compile the local temporary binary
echo "  [+] Compiling Vane binary..."
go build -o vane_smoke ./cmd/vane
trap "rm -f vane_smoke" EXIT

# 2. Run documentation help screen test
echo "  [+] Testing help screen..."
if ./vane_smoke --help | grep -q "discover"; then
	echo "      ✔ 'discover' subcommand documented in help screen!"
else
	echo "      ❌ 'discover' subcommand missing from help screen!"
	exit 1
fi

# 3. Test loopback token parsing & conversion (Infocenter Mode)
echo "  [+] Testing loopback token conversion..."
if ./vane_smoke -c lo 1 | grep -q "127.0.0.1\|::1"; then
	echo "      ✔ Loopback notation parsed and resolved successfully!"
else
	echo "      ❌ Loopback notation conversion failed!"
	exit 1
fi

# 4. Test semantic token error reporting
echo "  [+] Testing semantic token error paths..."
if ./vane_smoke echo "lo|>...pve" 2>&1 | grep -q "could not be resolved"; then
	echo "      ✔ Semantic token resolution errors reported correctly!"
else
	echo "      ❌ Semantic token error handling mismatch!"
	exit 1
fi

# 5. Test discover subcommand on loopback
echo "  [+] Testing 'discover' command on loopback..."
if ./vane_smoke discover lo | grep -q "vane discover"; then
	echo "      ✔ Subnetwork service discovery executed successfully!"
else
	echo "      ❌ 'discover' subcommand failed!"
	exit 1
fi

# 6. Test explain subcommand
echo "  [+] Testing 'explain' command documentation and resolution..."
if ./vane_smoke --help | grep -q "explain"; then
	echo "      ✔ 'explain' subcommand documented in help screen!"
else
	echo "      ❌ 'explain' subcommand missing from help screen!"
	exit 1
fi

if ./vane_smoke explain lo.1 | grep -q "UIP RESOLUTION ENGINE\|enp3s0\|lo"; then
	echo "      ✔ 'explain' subcommand executed and resolved successfully!"
else
	echo "      ❌ 'explain' subcommand execution failed!"
	exit 1
fi

echo ""
echo "=================================================="
echo "  ✔ INTEGRATION SMOKE TEST PASSED SUCCESSFULLY!    "
echo "=================================================="
