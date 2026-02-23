#!/bin/bash
LOG_DIR="./log"

# If not passed, it will default to false
CLEAR_LOGS=true

# If the clear logs flag is passed, clear the logs
if [ "$CLEAR_LOGS" = true ]; then
    rm -rf $LOG_DIR
fi



# run from the root of the repo
cd testnet
./reset.sh
cd ..

# run the testnet
cargo run --bin testnet -- --log-dir $LOG_DIR