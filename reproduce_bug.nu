#!/usr/bin/env nu

# Script to reproduce the w3name validityType bug
# This script builds the project and attempts to publish a test value

print "🔧 Building w3name project..."
cargo build

if ($env.LAST_EXIT_CODE != 0) {
    print "❌ Build failed"
    exit 1
}

print "✅ Build successful"

print "🔑 Creating test key..."
let binary_path = "./target/debug/w3name"
let key_file = "test-bug-reproduce.key"

# Create a new keypair for testing
^$binary_path create --output $key_file

if ($env.LAST_EXIT_CODE != 0) {
    print "❌ Failed to create test key"
    exit 1
}

print $"✅ Created test key: ($key_file)"

print "📤 Attempting to publish test value..."
let test_value = "/ipfs/baguqeerav7qzu4nyltd53bjfbtvsl7kmbuktjvkywlvlw6mrvjf47mhuxnkq"

# Attempt to publish - this should reproduce the bug
let result = (do { ^$binary_path publish --key $key_file --value $test_value } | complete)

if ($result.exit_code == 0) {
    print "✅ Initial publish successful!"
    print $result.stdout

    print ""
    print "📤 Now attempting to UPDATE the same record with a new value..."
    let test_value2 = "/ipfs/bafkreiem4twkqzsq2aj4shbycd4yvoj2cx72vezicletlhi7dijjciqpui"

    # Attempt to update - this is where it previously failed
    let result2 = (do { ^$binary_path publish --key $key_file --value $test_value2 } | complete)

    if ($result2.exit_code == 0) {
        print "✅ Update successful! Bug is FULLY FIXED!"
        print $result2.stdout
        print ""
        print "🎉 Both create and update operations work correctly!"
    } else {
        print "❌ Update failed - bug partially fixed"
        print "Exit code:" $result2.exit_code
        print "Error output:"
        print $result2.stderr
        print ""
        print "⚠️ Can create new IPNS records but cannot update them"
    }
} else {
    print "❌ Initial publish failed - bug reproduced!"
    print "Exit code:" $result.exit_code
    print "Error output:"
    print $result.stderr

    # Check if it's the specific validityType error
    if ($result.stderr | str contains "validityType") {
        print ""
        print "🐛 Confirmed: This is the validityType field mismatch bug from issue #35"
    }
}

print ""
print "🧹 Cleaning up test key..."
rm -f $key_file
