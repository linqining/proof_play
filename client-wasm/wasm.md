<https://developer.mozilla.org/zh-CN/docs/WebAssembly/Guides/Rust_to_Wasm>
最新文档 <https://github.com/wasm-bindgen/wasm-bindgen>

// rust编译wasm
wasm-pack build --scope linqining --target web

// wasm-pack build --scope linqining --target no-modules 纯js

// blscurve build

```shellscript
WASI_SDK_PATH=$HOME/.wasi-sdk \
CC="$HOME/.wasi-sdk/bin/clang --sysroot=$HOME/.wasi-sdk/share/wasi-sysroot" \
AR="$HOME/.wasi-sdk/bin/ar" \
wasm-pack build --scope linqining --target web
```

//发布npm
npm publish --access=public
