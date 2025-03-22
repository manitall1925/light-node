#!/bin/bash

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <local_repo_path>"
  exit 1
fi

REPO_PATH="$1"
SERVER_ENDPOINT="http://localhost:8080"

if [ ! -d "$REPO_PATH" ]; then
  echo "Error: Directory $REPO_PATH does not exist."
  exit 1
fi

cd "$REPO_PATH" || exit 1

check_server_running() {
  while ! curl -s $SERVER_ENDPOINT/ > /dev/null; do
    echo "Waiting for the Rust server to start"
    sleep 10
  done
  echo "Rust server is running."
}

echo "Starting Rust server"
cargo run &> server.log &
SERVER_PID=$!

check_server_running

echo "Enter data for the Merkle Tree (comma-separated, e.g., data1,data2,data3):"
read -r MERKLE_DATA
IFS=',' read -r -a DATA_ARRAY <<< "$MERKLE_DATA"

DATA_JSON=$(printf '"%s",' "${DATA_ARRAY[@]}" | sed 's/,$//')

echo "Inserting data into the Merkle Tree"
INSERT_RESPONSE=$(curl -s -X POST $SERVER_ENDPOINT/process \
  -H "Content-Type: application/json" \
  -d "{
        \"operation\": \"insert\",
        \"data\": [$DATA_JSON],
        \"proof_request\": null,
        \"proof\": null
      }")
MERKLE_ROOT=$(echo "$INSERT_RESPONSE" | jq -r '.root')
echo "Merkle Root: $MERKLE_ROOT"

for LEAF_DATA in "${DATA_ARRAY[@]}"; do
  echo "Generating Merkle proof for leaf data: $LEAF_DATA"
  PROOF_RESPONSE=$(curl -s -X POST $SERVER_ENDPOINT/process \
    -H "Content-Type: application/json" \
    -d "{
          \"operation\": \"prove\",
          \"data\": [$DATA_JSON],
          \"proof_request\": \"$LEAF_DATA\",
          \"proof\": null
        }")
  MERKLE_PROOF=$(echo "$PROOF_RESPONSE" | jq -c '.proof')
  echo "Merkle Proof for $LEAF_DATA: $MERKLE_PROOF"

  echo "Verifying Merkle proof for leaf data: $LEAF_DATA"
  VERIFY_RESPONSE=$(curl -s -X POST $SERVER_ENDPOINT/process \
    -H "Content-Type: application/json" \
    -d "{
          \"operation\": \"verify\",
          \"data\": [$DATA_JSON],
          \"proof_request\": null,
          \"proof\": $MERKLE_PROOF
        }")
  VERIFIED=$(echo "$VERIFY_RESPONSE" | jq -r '.verified')
  echo "Proof Verified for $LEAF_DATA: $VERIFIED"
done

echo "Stopping Rust server"
kill "$SERVER_PID"

echo "Done"
echo "Final Merkle Root: $MERKLE_ROOT"
