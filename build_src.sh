#!/usr/bin/env bash

echo "Build target rust"
cargo b --release --package millegrilles_grosfichiers --bin millegrilles_grosfichiers
