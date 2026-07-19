package powdata

import _ "embed"

//go:embed pow.wasm
var WASMBinary []byte

//go:embed pow_glue.js
var PowGlueJS []byte
