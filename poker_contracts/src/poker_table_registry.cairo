//! PokerTableRegistry — 桌台注册表（不可变行 + 只追加生命周期）。
//!
//! 设计（docs 讨论定稿，2026-09-11）：注册表只回答两个问题——"这张桌
//! 承诺过什么规则"与"这张桌还开着吗"。它**不碰钱**（资金在 PokerVault），
//! 也不进任何证明约束；其价值在于：
//! 1. `table_id` 由合约分配（内部计数器自增），服务端不能选、不能撞，
//!    是唯一不需要信任服务端的 id 唯一性来源；
//! 2. `params_hash` 建桌时一次性钉死（承诺，非明文——不泄漏盲注等元数据），
//!    永不提供修改入口。规则变更 = 关旧桌 + 开新桌（新 id 新行）；
//! 3. `close_table` 之后 `is_open == false`：客户端与运营流程以它为
//!    "不再开局"的权威信号。恶意宿主自报 table_id 可绕过链上检查——
//!    注册表是绊线与审计轨迹，不是缰绳。
//!
//! 生命周期（只追加，无 update）：`Vacant → Open → Closed`（终态）。
//!
//! 权限：
//! - `create_table` permissionless（注册表不碰钱，任何人可登记桌台）；
//! - `close_table`：creator 或合约 owner 随时可关（owner 为运营兜底）；
//!   闲置超过 `close_grace_secs` 后任何人可关（遗桌清理，对齐 vault 的
//!   `unlock_after_deadline` permissionless 哲学）。
//!
//! 存储形态：记录字段拆为平行 Map（TableRecord 仅作 view 返回聚合），
//! 规避 struct-in-Map 在 cairo 2.11/2.19 间的 storage 语义差异。

use starknet::ContractAddress;

/// 未登记（storage 默认零值语义）。
pub const STATUS_VACANT: u8 = 0;
/// 开放中（可入座、可开局）。
pub const STATUS_OPEN: u8 = 1;
/// 已关闭（终态：不再接受入座、不再开局）。
pub const STATUS_CLOSED: u8 = 2;

#[derive(Copy, Drop, Serde, PartialEq, Debug)]
pub struct TableRecord {
    /// Poseidon 承诺（服务端公式：`poseidon_hash_many([max_players,
    /// small_blind, big_blind])`，字段顺序即契约）。0 = 未登记。
    pub params_hash: felt252,
    pub creator: ContractAddress,
    pub status: u8,
    pub created_at: u64,
    pub closed_at: u64,
}

#[starknet::interface]
pub trait IPokerTableRegistry<TContractState> {
    /// 登记新桌台，返回合约分配的全局唯一 `table_id`（从 1 递增）。
    fn create_table(ref self: TContractState, params_hash: felt252) -> u64;
    /// 关闭桌台（终态）。creator/owner 随时可调；他人须等
    /// `created_at + close_grace_secs`。
    fn close_table(ref self: TContractState, table_id: u64);
    /// 桌台记录（未登记 id 返回全零 record，`status == STATUS_VACANT`）。
    fn get_table(self: @TContractState, table_id: u64) -> TableRecord;
    /// 已登记且处于 Open 状态。未登记 id 返回 false。
    fn is_open(self: @TContractState, table_id: u64) -> bool;
    /// 已分配的 id 数（下一个 id = count + 1）。
    fn table_count(self: @TContractState) -> u64;
    /// 闲置关桌宽限期（秒），constructor 注入。
    fn close_grace_secs(self: @TContractState) -> u64;
    /// 合约 owner（运营兜底关闭主体）。
    fn owner(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PokerTableRegistry {
    use core::num::traits::Zero;
    use starknet::{
        ContractAddress, get_caller_address, get_block_timestamp,
        storage::{
            Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
            StoragePointerWriteAccess,
        },
    };

    use super::{TableRecord, STATUS_CLOSED, STATUS_OPEN};

    #[storage]
    struct Storage {
        /// 桌台规则承诺（不可变：无任何写入口除 create_table）。
        params_hash: Map<u64, felt252>,
        /// 建桌账户。
        creators: Map<u64, ContractAddress>,
        /// 生命周期状态（Vacant=0 / Open=1 / Closed=2）。
        statuses: Map<u64, u8>,
        created_at: Map<u64, u64>,
        closed_at: Map<u64, u64>,
        /// 已分配 id 计数（下一 id = count + 1；从 1 起，0 永不分配，
        /// 使 0 可作 Rust 侧 Option<u64> 的天然哨兵）。
        table_count: u64,
        /// 闲置关桌宽限期（秒）。0 = 建桌后任何人立即可关（测试用）。
        close_grace_secs: u64,
        /// 运营兜底关闭主体。
        owner: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        TableCreated: TableCreated,
        TableClosed: TableClosed,
    }

    #[derive(Drop, starknet::Event)]
    struct TableCreated {
        table_id: u64,
        params_hash: felt252,
        creator: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct TableClosed {
        table_id: u64,
        closed_at: u64,
        /// 执行关闭的账户（creator / owner / 过期后任意第三方）。
        by: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress, close_grace_secs: u64) {
        assert!(!owner.is_zero(), "owner required");
        self.owner.write(owner);
        self.close_grace_secs.write(close_grace_secs);
    }

    #[abi(embed_v0)]
    pub impl PokerTableRegistryImpl of super::IPokerTableRegistry<ContractState> {
        fn create_table(ref self: ContractState, params_hash: felt252) -> u64 {
            assert!(params_hash != 0, "params hash required");
            let table_id = self.table_count.read() + 1;
            let creator = get_caller_address();
            self.params_hash.write(table_id, params_hash);
            self.creators.write(table_id, creator);
            self.statuses.write(table_id, STATUS_OPEN);
            self.created_at.write(table_id, get_block_timestamp());
            self.closed_at.write(table_id, 0);
            self.table_count.write(table_id);
            self.emit(TableCreated { table_id, params_hash, creator });
            table_id
        }

        fn close_table(ref self: ContractState, table_id: u64) {
            let status = self.statuses.read(table_id);
            assert!(status == STATUS_OPEN, "table not open");
            let caller = get_caller_address();
            let is_authorized = caller == self.creators.read(table_id)
                || caller == self.owner.read()
                || get_block_timestamp()
                    >= self.created_at.read(table_id) + self.close_grace_secs.read();
            assert!(is_authorized, "close not permitted yet");
            self.statuses.write(table_id, STATUS_CLOSED);
            self.closed_at.write(table_id, get_block_timestamp());
            self.emit(TableClosed { table_id, closed_at: get_block_timestamp(), by: caller });
        }

        fn get_table(self: @ContractState, table_id: u64) -> TableRecord {
            TableRecord {
                params_hash: self.params_hash.read(table_id),
                creator: self.creators.read(table_id),
                status: self.statuses.read(table_id),
                created_at: self.created_at.read(table_id),
                closed_at: self.closed_at.read(table_id),
            }
        }

        fn is_open(self: @ContractState, table_id: u64) -> bool {
            self.statuses.read(table_id) == STATUS_OPEN
        }

        fn table_count(self: @ContractState) -> u64 {
            self.table_count.read()
        }

        fn close_grace_secs(self: @ContractState) -> u64 {
            self.close_grace_secs.read()
        }

        fn owner(self: @ContractState) -> ContractAddress {
            self.owner.read()
        }
    }
}

#[cfg(test)]
mod tests {
    use starknet::{ContractAddress, get_contract_address};
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
    use snforge_std::cheatcodes::execution_info::block_timestamp::{
        start_cheat_block_timestamp_global,
    };
    use snforge_std::cheatcodes::execution_info::caller_address::{
        start_cheat_caller_address, stop_cheat_caller_address,
    };

    use super::{
        IPokerTableRegistryDispatcher, IPokerTableRegistryDispatcherTrait, TableRecord,
        STATUS_CLOSED, STATUS_OPEN, STATUS_VACANT,
    };

    fn deploy_contract(name: ByteArray, calldata: @Array<felt252>) -> ContractAddress {
        let class = declare(name).unwrap().contract_class();
        let (address, _) = class.deploy(calldata).unwrap();
        address
    }

    /// 返回 (registry, owner, creator)；`grace_secs` = 闲置关桌宽限期。
    fn setup(grace_secs: u64) -> (
        ContractAddress,
        ContractAddress,
        ContractAddress,
        IPokerTableRegistryDispatcher,
    ) {
        // snforge 默认块时间戳为 0，created_at/closed_at 的 "已设置" 断言
        // 需要一个非零基准时间戳（宽限期相对语义不受具体值影响）。
        start_cheat_block_timestamp_global(1000);
        let owner: ContractAddress = 0x09e7.try_into().unwrap();
        let registry = deploy_contract(
            "PokerTableRegistry",
            @array![owner.into(), grace_secs.into()],
        );
        (
            registry,
            owner,
            get_contract_address(),
            IPokerTableRegistryDispatcher { contract_address: registry },
        )
    }

    fn outsider() -> ContractAddress {
        0xdead_beef.try_into().unwrap()
    }

    const PARAMS_A: felt252 = 0xabc;
    const PARAMS_B: felt252 = 0xdef;

    #[test]
    fn create_assigns_sequential_ids_and_record() {
        let (_, owner, creator, reg) = setup(86400);

        let id1 = reg.create_table(PARAMS_A);
        let id2 = reg.create_table(PARAMS_B);

        assert!(id1 == 1, "first id must be 1");
        assert!(id2 == 2, "ids must increment");
        assert!(reg.table_count() == 2, "count mismatch");

        let record: TableRecord = reg.get_table(id1);
        assert!(record.params_hash == PARAMS_A, "params hash mismatch");
        assert!(record.creator == creator, "creator mismatch");
        assert!(record.status == STATUS_OPEN, "status must be Open");
        assert!(record.created_at > 0, "created_at must be set");
        assert!(record.closed_at == 0, "closed_at must be unset");
        assert!(reg.is_open(id1), "table must be open");
        assert!(reg.owner() == owner, "owner mismatch");
    }

    #[test]
    fn vacant_table_is_not_open() {
        let (_, _, _, reg) = setup(86400);
        assert!(!reg.is_open(42), "vacant id must not be open");
        let record: TableRecord = reg.get_table(42);
        assert!(record.status == STATUS_VACANT, "vacant status mismatch");
    }

    #[test]
    fn creator_can_close_and_close_is_terminal() {
        let (_, _, _, reg) = setup(86400);
        let id = reg.create_table(PARAMS_A);

        reg.close_table(id);

        assert!(!reg.is_open(id), "closed table must not be open");
        let record: TableRecord = reg.get_table(id);
        assert!(record.status == STATUS_CLOSED, "status must be Closed");
        assert!(record.closed_at > 0, "closed_at must be set");
        assert!(record.params_hash == PARAMS_A, "params hash must be preserved");
    }

    #[test]
    #[should_panic(expected: "table not open")]
    fn double_close_reverts() {
        let (_, _, _, reg) = setup(86400);
        let id = reg.create_table(PARAMS_A);
        reg.close_table(id);
        reg.close_table(id);
    }

    #[test]
    fn owner_can_close_any_open_table() {
        let (_, owner, _, reg) = setup(86400);
        let id = reg.create_table(PARAMS_A);
        start_cheat_caller_address(reg.contract_address, owner);
        reg.close_table(id);
        stop_cheat_caller_address(reg.contract_address);
        assert!(!reg.is_open(id), "owner close must take effect");
    }

    #[test]
    #[should_panic(expected: "close not permitted yet")]
    fn outsider_cannot_close_within_grace() {
        // grace = 1 天：建桌后同块时间调用必在宽限期内 → 拒绝
        let (_, _, _, reg) = setup(86400);
        let id = reg.create_table(PARAMS_A);
        start_cheat_caller_address(reg.contract_address, outsider());
        reg.close_table(id);
    }

    #[test]
    fn outsider_can_close_zero_grace_table() {
        // grace = 0：created_at + 0 ≤ 当前块时间 → 任何人立即可关（遗桌清理路径）
        let (_, _, _, reg) = setup(0);
        let id = reg.create_table(PARAMS_A);
        start_cheat_caller_address(reg.contract_address, outsider());
        reg.close_table(id);
        stop_cheat_caller_address(reg.contract_address);
        assert!(!reg.is_open(id), "grace-expired close must take effect");
    }
}
