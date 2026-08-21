WASM_OUT = ../internal/waf/challenge/powdata
WASM_FILE = $(WASM_OUT)/pow.wasm
GLUE_FILE = $(WASM_OUT)/pow_glue.js

.PHONY: build optimize clean

build:
	wasm-pack build --target no-modules --release --out-dir pkg --out-name pow
	cp pkg/pow_bg.wasm $(WASM_FILE)
	cp pkg/pow.js $(GLUE_FILE)

optimize: build
	wasm-pack build --target no-modules --release --out-dir pkg --out-name pow
	npx terser $(GLUE_FILE) \
		--compress passes=3,pure_getters=true,unsafe=true,unsafe_math=true,unsafe_comps=true \
		--mangle toplevel=true,reserved='["wasm_bindgen"]' \
		--output $(GLUE_FILE)

	npx javascript-obfuscator $(GLUE_FILE) --output $(GLUE_FILE)  \
		--compact true \
		--control-flow-flattening true \
		--dead-code-injection true \
		--string-array true \
		--string-array-encoding rc4 \
		--self-defending true


	@echo "WASM: $$(wc -c < $(WASM_FILE)) bytes"
	@echo "Glue: $$(wc -c < $(GLUE_FILE)) bytes"

clean:
	cargo clean
	rm -rf pkg
