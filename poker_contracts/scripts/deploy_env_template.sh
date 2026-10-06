# 部署前置（需用户提供的真实凭据/资金，脚本无法自动完成）：
# 1. 安装 starknet-foundry: curl -L https://raw.githubusercontent.com/foundry-rs/starknet-foundry/master/scripts/install.sh | sh
# 2. 准备一个有 Sepolia STRK 的账户（sncast account create + 水龙头充值）
# 3. 导出以下环境变量后执行 scripts/deploy_sepolia.sh：
#    export SNCAST_ACCOUNT=<account-name>
#    export SNCAST_URL=https://starknet-sepolia.public.blastapi.io/rpc/v0_8
#    export OWNER=<owner-address>  PROVER=<operator-address>  INITIAL_SUPPLY=<wei>
# 4. 部署产出写入 poker_texas_air/strk20.json 与 server/client env：
#    server .env: STARKNET_SETTLEMENT_ADDRESS / STARKNET_VAULT_ADDRESS /
#                 STARKNET_STRK_ADDRESS / STARKNET_OPERATOR_ADDRESS / STARKNET_OPERATOR_PRIVATE_KEY
#    client .env: VITE_POKER_VAULT_ADDRESS / VITE_POKER_SETTLEMENT_ADDRESS
