#!/bin/bash

set -e

rm -r /tmp/test_* || true; cargo test $@ -- --test-threads=1
# rm -r /tmp/test_*; cargo test test_lock_coins_flag -- --ignored
