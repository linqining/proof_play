// 私密领取（OP_WITHDRAW）helper 腿的 Sepolia fork 复现。
//
// 现象：浏览器私密领取在 paymaster 模拟阶段 156
// TRANSACTION_EXECUTION_ERROR（链上无回执，无法查 revert）。
// 本测试在真实 Sepolia 状态上用 cheat 伪装池地址（STRK20 池在
// 链上调 privacy_invoke 时的真实 caller）直接执行 helper 腿：
// 若断言在腿内触发，snforge 会打印合约里的原始 panic 消息。
//
// 前置状态（2026-09-19 实测）：
//   player 0x017c…706e chip_balance = 4.837e18 wei，locked = 0；
//   vault STRK 背书 16.2 STRK；unshield_helper = 本 anonymizer；
//   anonymizer class 0x525646bd（与 2026-09-07 部署记录一致）。
//
// 接口按链上 ABI 内联声明（lib.cairo 的合约模块对 tests 不 pub，
// dispatcher 按选择器路由，声明等价即可）。

use starknet::ContractAddress;
use snforge_std::{start_cheat_caller_address, stop_cheat_caller_address};

/// Sepolia 在网 PokerVaultAnonymizer（P1-2 类，2026-09-19 重部署）。
const ANONYMIZER: felt252 = 0x335db85a326271f23e7c199b464e67200d8c9fa7570da9807f50ed31fcddf4e;
/// Sepolia STRK20 privacy pool（strk20-by-example.org/contract-addresses，
/// 2026-09-03 核验；anonymizer 构造参数同址）。
const SEPOLIA_POOL: felt252 = 0x254a6b2997ef52e9f830ce1f543f6b29768295e8d17e2267d672c552cfe0d91;
/// 复现用户：当前在牌桌的 Ready 钱包（新 vault 持有 990 chips）。
const PLAYER: felt252 = 0x1c390e6ccb66395db6d244fb485a46e8fdc28b5f9a1413ec7ab7df6fff802da;
/// 新 vault（玩家筹码所在，anonymizer.vault 构造绑定）。
const VAULT: felt252 = 0x1b1b7b37a14ac3b53930d2c5704a08c482d1d6b800626011f799b29f1549438;

/// 与合约 privacy::objects::OpenNoteDeposit 同形（note_id, token, u128 金额）。
#[derive(Drop, Serde)]
struct OpenNoteDepositFork {
    note_id: felt252,
    token: ContractAddress,
    amount: u128,
}

#[starknet::interface]
trait IVaultChipBalanceFork<TContractState> {
    fn chip_balance(self: @TContractState, player: starknet::ContractAddress) -> u256;
}

#[starknet::interface]
trait IAnonymizerFork<TContractState> {
    fn privacy_invoke(
        ref self: TContractState,
        operation: felt252,
        player: ContractAddress,
        amount: u256,
        note_id: felt252,
    ) -> Span<OpenNoteDepositFork>;
}

/// 与 ClaimRewardsModal 的提交同形：OP_WITHDRAW + 全额（locked=0）。
#[fork("SEPOLIA_LATEST")]
#[test]
fn unshield_leg_repro_on_sepolia_state() {
    let anonymizer: ContractAddress = ANONYMIZER.try_into().unwrap();
    let pool: ContractAddress = SEPOLIA_POOL.try_into().unwrap();
    let player: ContractAddress = PLAYER.try_into().unwrap();
    // 动态读余额：玩家在旧 vault 的筹码会随游戏/迁移变动，硬编码金额
    // 会在余额下降后以 "Insufficient chip balance" 假失败。
    let mut vault = IVaultChipBalanceForkDispatcher { contract_address: VAULT.try_into().unwrap() };
    let amount = vault.chip_balance(player);
    assert(amount > 0, 'player balance is zero');

    start_cheat_caller_address(anonymizer, pool);
    let mut dispatcher = IAnonymizerForkDispatcher { contract_address: anonymizer };
    let deposits = dispatcher.privacy_invoke(1, player, amount, 0xdeadbeef);
    stop_cheat_caller_address(anonymizer);

    assert(deposits.len() == 1, 'expected exactly one deposit');
    let deposit = deposits.at(0);
    assert(*deposit.note_id == 0xdeadbeef, 'note id mismatch');
    assert(*deposit.amount > 0, 'out amount must be positive');
}
