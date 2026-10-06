# 顶层任务入口。日常联调的主路径是 scripts/dev.sh（开关见其头注释），
# 这里只列常用别名；fund / 端口覆盖等高级用法直接用 bash scripts/dev.sh。

.PHONY: dev wasm site site-serve client check help

dev: ## 一键联调：devnet + 合约部署 + texas 服务器 + 前端（wasm 缺失/过期自动重建）
	bash scripts/dev.sh

wasm: ## 构建 client-wasm → client-wasm/pkg/（前端 link:../client-wasm/pkg 依赖）
	wasm-pack build client-wasm --target web

site: ## 构建官网静态站 → website/dist/
	python3 website/build.py

site-serve: site ## 构建官网并在 :8080 预览
	cd website/dist && python3 -m http.server 8080

client: ## 仅前端 dev server（wasm 与服务器需自行准备）
	cd client && pnpm dev

check: ## Rust 工作区测试
	cargo test --workspace

help: ## 列出可用目标
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ?' '{printf "  make %-11s %s\n", $$1, $$2}'
