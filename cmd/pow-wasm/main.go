//go:build js && wasm

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"syscall/js"
)

// VM opcodes — wraps the SHA-256 solve loop in a lightweight stack machine
// so the core algorithm isn't directly visible in the WASM binary.
const (
	opLoadNonce   byte = 0x10
	opLoadCounter byte = 0x11
	opConcat      byte = 0x12
	opSHA256      byte = 0x13
	opCheckPrefix byte = 0x14
	opIncCounter  byte = 0x15
	opReturnOK    byte = 0x16
	opReturnFail  byte = 0x17
	opLoop        byte = 0x18
	opYield       byte = 0x19
)

type vm struct {
	nonce      string
	counter    int64
	difficulty int
	prefix     string
	stack      [4]string
	sp         int
	lastHash   string
}

func (v *vm) push(s string) { v.stack[v.sp] = s; v.sp++ }
func (v *vm) pop() string   { v.sp--; return v.stack[v.sp] }

func (v *vm) exec(program []byte) (found bool) {
	pc := 0
	for pc < len(program) {
		op := program[pc]
		pc++
		switch op {
		case opLoadNonce:
			v.push(v.nonce)
		case opLoadCounter:
			v.push(fmt.Sprintf("%d", v.counter))
		case opConcat:
			b := v.pop()
			a := v.pop()
			v.push(a + b)
		case opSHA256:
			msg := v.pop()
			h := sha256.Sum256([]byte(msg))
			v.lastHash = hex.EncodeToString(h[:])
			v.push(v.lastHash)
		case opCheckPrefix:
			hash := v.pop()
			if len(hash) >= v.difficulty && hash[:v.difficulty] == v.prefix {
				return true // Found valid PoW solution
			}
		case opIncCounter:
			v.counter++
		case opReturnOK:
			return true
		case opReturnFail:
			return false
		case opLoop, opYield:
			// No-op in this simplified VM
		case 0x00: // NOP
			// skip
		}
	}
	return false
}

// solveBatch runs a batch of PoW iterations inside the VM.
func solveBatch(nonce string, startCounter int64, difficulty, batchSize int, program []byte) (bool, int64, string) {
	prefix := ""
	for i := 0; i < difficulty; i++ {
		prefix += "0"
	}

	v := &vm{
		nonce:      nonce,
		counter:    startCounter,
		difficulty: difficulty,
		prefix:     prefix,
	}

	for i := 0; i < batchSize; i++ {
		v.sp = 0
		if v.exec(program) {
			return true, v.counter, v.lastHash
		}
		v.counter++
	}

	return false, v.counter, ""
}

// defaultProgram is the standard PoW bytecode sequence.
var defaultProgram = []byte{
	opLoadNonce,
	opLoadCounter,
	opConcat,
	opSHA256,
	opCheckPrefix,
}

func main() {
	done := make(chan struct{})

	// Export solve_batch: (nonce, startCounter, difficulty, batchSize, programHex) -> {found, counter, hash}
	js.Global().Set("__wasm_pow_solve_batch", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 4 {
			return nil
		}
		nonce := args[0].String()
		startCounter := int64(args[1].Float())
		difficulty := args[2].Int()
		batchSize := args[3].Int()

		var program []byte
		if len(args) > 4 && args[4].Type() == js.TypeString {
			progHex := args[4].String()
			if decoded, err := hex.DecodeString(progHex); err == nil {
				program = decoded
			}
		}
		if program == nil {
			program = defaultProgram
		}

		found, counter, hash := solveBatch(nonce, startCounter, difficulty, batchSize, program)

		result := js.Global().Get("Object").New()
		result.Set("found", found)
		result.Set("counter", counter)
		result.Set("hash", hash)
		return result
	}))

	// Export solve_full: (nonce, difficulty, programHex) -> starts async solve using setTimeout batching
	js.Global().Set("__wasm_pow_solve", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return nil
		}
		nonce := args[0].String()
		difficulty := args[1].Int()

		var program []byte
		if len(args) > 2 && args[2].Type() == js.TypeString {
			progHex := args[2].String()
			if decoded, err := hex.DecodeString(progHex); err == nil {
				program = decoded
			}
		}
		if program == nil {
			program = defaultProgram
		}

		prefix := ""
		for i := 0; i < difficulty; i++ {
			prefix += "0"
		}

		// Use setTimeout-based batch solving to avoid blocking the JS event loop.
		// This avoids Go goroutine/channel scheduling issues in WASM.
		var counter int64
		batchSize := 50000

		var solveFn js.Func
		solveFn = js.FuncOf(func(this js.Value, args []js.Value) any {
			v := &vm{
				nonce:      nonce,
				counter:    counter,
				difficulty: difficulty,
				prefix:     prefix,
			}

			for i := 0; i < batchSize; i++ {
				v.sp = 0
				if v.exec(program) {
					// Found!
					jsResult := js.Global().Get("Object").New()
					jsResult.Set("nonce", nonce)
					jsResult.Set("counter", v.counter)
					jsResult.Set("hash", v.lastHash)
					jsResult.Set("difficulty", difficulty)
					js.Global().Set("__powResult", jsResult)

					cb := js.Global().Get("__owaf_pow_callback")
					if cb.Truthy() {
						cb.Invoke(v.counter, v.lastHash)
					}
					solveFn.Release()
					return nil
				}
				v.counter++
			}

			// Not found yet, schedule next batch
			counter = v.counter
			js.Global().Call("setTimeout", solveFn, 0)
			return nil
		})

		// Start first batch immediately via setTimeout(0) to not block WASM init
		js.Global().Call("setTimeout", solveFn, 0)
		return nil
	}))

	// Signal ready
	js.Global().Set("__wasm_pow_ready", true)
	readyCb := js.Global().Get("__onWasmReady")
	if readyCb.Truthy() {
		readyCb.Invoke()
	}

	<-done
}
