#!/bin/bash

# Build script for Regorus WASM bindings
# This script compiles the Rust code to WebAssembly and generates JavaScript bindings

set -e

echo "🧹 Cleaning previous build artifacts..."
cargo clean

echo "🎯 Building WASM target..."
RUSTFLAGS="--cfg getrandom_backend=\"wasm_js\"" cargo build --target wasm32-unknown-unknown --release

echo "🔗 Generating JavaScript bindings..."
wasm-bindgen --target nodejs --out-dir pkg target/wasm32-unknown-unknown/release/regorusjs.wasm

echo "✅ Build complete! Generated files:"
ls -la pkg/

echo "🧪 Running test..."
node test.js

echo "🎉 WASM build successful!"
