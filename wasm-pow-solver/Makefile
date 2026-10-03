WASM_OUT = ../internal/waf/challenge/powdata
WASM_FILE = $(WASM_OUT)/pow.wasm
GLUE_FILE = $(WASM_OUT)/pow_glue.js
GLUE_PKG = pkg/pow.js

.PHONY: build optimize clean

build:
	wasm-pack build --target no-modules --release --out-dir pkg --out-name pow
	cp pkg/pow_bg.wasm $(WASM_FILE)
	@if [ -f $(GLUE_FILE) ] && grep -q "function _0x" $(GLUE_FILE) 2>/dev/null; then \
		echo "build: $(GLUE_FILE) is obfuscated; leaving it untouched."; \
		echo "build: pkg/pow.js holds the fresh unobfuscated glue."; \
		echo "build: run 'make optimize' to regenerate an obfuscated $(GLUE_FILE)."; \
	else \
		cp $(GLUE_PKG) $(GLUE_FILE); \
	fi
#   FORCE_GLUE=1 make optimize  -> 强制用 pkg/pow.js 重新生成 glue
#   make optimize（默认）        -> 复用现有混淆 glue，并打印跳过原因
optimize: build
	@if [ -n "$(FORCE_GLUE)" ]; then \
		echo "optimize: FORCE_GLUE=1 set, regenerating glue from $(GLUE_PKG)"; \
		cp $(GLUE_PKG) $(GLUE_FILE); \
	elif [ ! -f $(GLUE_FILE) ] || ! grep -q "function _0x" $(GLUE_FILE) 2>/dev/null; then \
		echo "optimize: $(GLUE_FILE) is plaintext, generating from $(GLUE_PKG)"; \
		cp $(GLUE_PKG) $(GLUE_FILE); \
	else \
		echo "optimize: reusing the existing obfuscated $(GLUE_FILE)."; \
		echo "optimize: Rust-side glue changes did NOT take effect; run 'FORCE_GLUE=1 make optimize' to regenerate."; \
	fi
	npx -y terser $(GLUE_FILE) \
		--compress passes=3,pure_getters=true,unsafe=true,unsafe_math=true,unsafe_comps=true \
		--mangle toplevel=true,reserved='["wasm_bindgen"]' \
		--output $(GLUE_FILE) 
	npx -y javascript-obfuscator $(GLUE_FILE) --output $(GLUE_FILE)  \
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
