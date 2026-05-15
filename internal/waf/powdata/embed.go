package powdata

import _ "embed"

//go:embed pow.wasm
var WASMBinary []byte

//go:embed wasm_exec.js
var WasmExecJS []byte
