#!/bin/bash

# Summary of findings:
# 1. The original error "Field 'validityType' did not match" was due to incorrect CBOR field casing
# 2. We fixed that by using camelCase field names in CBOR serialization
# 3. Now the server says "The validity type is unsupported" for value 0
# 4. Value 0 (EOL) is the ONLY defined validity type in the IPNS spec
# 5. The w3name service appears to have a bug or breaking change

echo "Testing current implementation..."
/home/manu/dev/ext/w3name/target/debug/w3name publish --key test-reproduce.key --value "/ipfs/baguqeerav7qzu4nyltd53bjfbtvsl7kmbuktjvkywlvlw6mrvjf47mhuxnkq" 2>&1

echo ""
echo "The root cause analysis:"
echo "1. Fixed: CBOR field names now use camelCase (validityType) to match server expectations"
echo "2. Issue: w3name service rejects validity_type=0 (EOL) despite it being the standard IPNS value"
echo "3. This appears to be a server-side bug or breaking change in the w3name service"