#!/usr/bin/env nu

# Script to test backward compatibility between old V2-only and new V1+V2 formats
# This simulates updating a record that was created with the old format

print "🧪 Testing backward compatibility: old V2-only → new V1+V2 format"
print ""

let binary_path = "./target/debug/w3name"
let key_file = "test-backward-compat.key"

# Step 1: Temporarily revert to old format (V2-only)
print "📝 Step 1: Reverting code to old V2-only format (commit 542a8bc)..."

# Save current version
git stash push -m "temp: save current changes for backward compat test"

# Checkout old version
git checkout 542a8bc -- w3name/src/ipns/mod.rs

print "✅ Code reverted to old V2-only format"
print ""

# Build with old format
print "🔧 Building with old format..."
do { cargo build --quiet } | complete | ignore

if ($env.LAST_EXIT_CODE != 0) {
    print "❌ Build failed"
    git restore w3name/src/ipns/mod.rs
    git stash pop
    exit 1
}

print "✅ Build successful"
print ""

# Create key and publish with old format
print "🔑 Creating test key..."
let create_result = (do { ^$binary_path create --output $key_file } | complete)

if ($create_result.exit_code != 0) {
    print "❌ Failed to create key"
    print $create_result.stderr
    git restore w3name/src/ipns/mod.rs
    git stash pop
    exit 1
}

print $"✅ Created test key: ($key_file)"
print ""

print "📤 Publishing FIRST value with OLD V2-only format..."
let test_value1 = "/ipfs/baguqeerav7qzu4nyltd53bjfbtvsl7kmbuktjvkywlvlw6mrvjf47mhuxnkq"

let result1 = (do { ^$binary_path publish --key $key_file --value $test_value1 } | complete)

if ($result1.exit_code != 0) {
    print "❌ First publish failed"
    print $result1.stderr
    git restore w3name/src/ipns/mod.rs
    git stash pop
    rm -f $key_file
    exit 1
}

print "✅ First publish successful with OLD format!"
print $result1.stdout
print ""

# Step 2: Restore to new format (V1+V2)
print "📝 Step 2: Restoring code to new V1+V2 format..."
git restore w3name/src/ipns/mod.rs
git stash pop

print "✅ Code restored to new format"
print ""

# Build with new format
print "🔧 Rebuilding with new format..."
do { cargo build --quiet } | complete | ignore

if ($env.LAST_EXIT_CODE != 0) {
    print "❌ Build failed"
    rm -f $key_file
    exit 1
}

print "✅ Build successful"
print ""

# Try to update the record with new format
print "📤 Attempting UPDATE with NEW V1+V2 format..."
let test_value2 = "/ipfs/bafkreiem4twkqzsq2aj4shbycd4yvoj2cx72vezicletlhi7dijjciqpui"

let result2 = (do { ^$binary_path publish --key $key_file --value $test_value2 } | complete)

if ($result2.exit_code == 0) {
    print "✅ UPDATE SUCCESSFUL! Backward compatibility works!"
    print $result2.stdout
    print ""
    print "🎉 Old V2-only records can be updated with new V1+V2 format!"
} else {
    print "❌ UPDATE FAILED - backward compatibility issue detected!"
    print "Exit code:" $result2.exit_code
    print "Error output:"
    print $result2.stderr
    print ""
    print "🐛 This is the bug: records created with old format cannot be updated with new format"
}

print ""
print "🧹 Cleaning up..."
rm -f $key_file
