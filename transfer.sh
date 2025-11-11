#!/bin/bash

# Load environment variables
source .env

# Get sender address from private key
FROM=$(cast wallet address $BUYER_PRIVATE_KEY)
TO="0x779f04fD2E864457Fb202401B447137CB9509a5C"
REGISTRY="0xe50769b2D9150bda3640b5f0059a40D68c3095ab"

echo "Transferring tokens from $FROM to $TO"
echo "Registry: $REGISTRY"
echo ""

# Transfer tokens 10-30
for TOKEN_ID in {10..30}
do
    echo "Transferring token ID: $TOKEN_ID"
    cast send $REGISTRY \
        "safeTransferFrom(address,address,uint256)" \
        $FROM \
        $TO \
        $TOKEN_ID \
        --rpc-url $BNB_TESTNET_RPC_URL \
        --private-key $BUYER_PRIVATE_KEY \
        --legacy

    if [ $? -eq 0 ]; then
        echo "✅ Token $TOKEN_ID transferred successfully"
    else
        echo "❌ Failed to transfer token $TOKEN_ID"
    fi
    echo ""
done

echo "Transfer complete!"
