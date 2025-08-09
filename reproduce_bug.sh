#!/usr/bin/env bash

# Script to reproduce the w3name validityType bug
# This script builds the project and attempts to publish a test value

set -e

echo "🔧 Building w3name project..."
cargo build

echo "✅ Build successful"

echo "🔑 Creating test key..."
BINARY_PATH="/home/manu/dev/ext/target/debug/w3name"
KEY_FILE="test-bug-reproduce.key"

# Create a new keypair for testing
cargo run -- create --output $KEY_FILE

echo "✅ Created test key: $KEY_FILE"

echo "📤 Attempting to publish test value..."
TEST_VALUE="/ipfs/bafkreiem4twkqzsq2aj4shbycd4yvoj2cx72vezicletlhi7dijjciqpui"

# Attempt to publish - this should now work with the fix
if cargo run -- publish --key $KEY_FILE --value $TEST_VALUE; then
    echo "✅ Publish successful! ValidityType bug has been fixed."
else
    EXIT_CODE=$?
    echo "❌ Publish failed - bug still exists!"
    echo "Exit code: $EXIT_CODE"
    echo ""
    echo "🐛 The validityType field mismatch bug from issue #35 persists"
fi

echo ""
echo "🧹 Cleaning up test key..."
rm -f $KEY_FILE