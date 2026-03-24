#!/bin/bash
# SDK E2E test runner — starts auth service via Go test harness, runs SDK tests, cleans up.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SDK_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
AUTH_DIR="$(cd "$SDK_DIR/../../../web3-opb-auth" && pwd)"

# Fixed test keypairs — must match harness constants in e2e/harness.go
ADMIN_PRIVATE_KEY="0ff2c38b76723d6a9a4419f76cdf5e5f686683c779c4af6eca00832b4261333f"
USER_PRIVATE_KEY="0b7c6594b9db0acf1c7ccd05d29b80ab00b973e0ea4262f4feebdcaca0a4ca3d"

echo "=== Starting auth service via E2E harness ==="

# Write a tiny Go test that starts the harness and blocks until killed
TEMP_TEST="${AUTH_DIR}/internal/e2e/sdk_bridge_test.go"
trap "rm -f '$TEMP_TEST' /tmp/sdk-e2e-auth-url" EXIT

cat > "$TEMP_TEST" << 'GOEOF'
package e2e

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
)

func TestSDKBridge(t *testing.T) {
	if os.Getenv("SDK_E2E_BRIDGE") != "1" {
		t.Skip("SDK_E2E_BRIDGE not set")
	}
	ts := NewTestServer(t)
	// Rewrite BaseURL to use localhost instead of 127.0.0.1 for SIWE domain matching
	baseURL := strings.Replace(ts.BaseURL, "127.0.0.1", "localhost", 1)
	fmt.Printf("AUTH_BASE_URL=%s\n", baseURL)

	// Write URL to file for SDK tests to read
	os.WriteFile("/tmp/sdk-e2e-auth-url", []byte(baseURL), 0644)

	// Block until signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
GOEOF

# Start the bridge in background
cd "$AUTH_DIR"
SDK_E2E_BRIDGE=1 go test ./internal/e2e/ -run TestSDKBridge -timeout 120s -v &
BRIDGE_PID=$!
trap "kill $BRIDGE_PID 2>/dev/null; rm -f '${TEMP_TEST}' /tmp/sdk-e2e-auth-url" EXIT

# Wait for auth URL file
echo "Waiting for auth service..."
for i in $(seq 1 30); do
	if [ -f /tmp/sdk-e2e-auth-url ]; then
		AUTH_URL=$(cat /tmp/sdk-e2e-auth-url)
		echo "Auth service ready at $AUTH_URL"
		break
	fi
	sleep 0.5
done

if [ -z "${AUTH_URL:-}" ]; then
	echo "ERROR: Auth service failed to start"
	exit 1
fi

echo "=== Running SDK E2E tests ==="
cd "$SDK_DIR"
AUTH_BASE_URL="$AUTH_URL" \
	ADMIN_PRIVATE_KEY="$ADMIN_PRIVATE_KEY" \
	USER_PRIVATE_KEY="$USER_PRIVATE_KEY" \
	go test -run "TestProject_" -v -count=1 -timeout 60s ./... 2>&1

echo "=== SDK E2E tests complete ==="
