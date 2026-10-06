//! 证明后端抽象：Mock（测试/bench 默认，确定性）与 Cli（真实链的服务器编排）。
//!
//! # 状态（如实）
//!
//! - [`MockBackend`]：本轮门禁与 K=2 测试的执行面。生成格式合规的叶信封
//!   （H1 为精确镜像），内部节点 digest 用**文档标注的测试替身**折叠——真实
//!   内部节点 digest 在 multiverifier 电路内计算（fold.rs:31-50 LayerEntry 承载），
//!   逐节点重算属 fact-verify `--aggregated` 交付，不在本 crate。
//! - [`CliBackend`]：真实链编排的参数装配（CLI 面与 vendored main.rs 逐旗核对）
//!   + fail-closed 内存闸门。**未在本轮实跑**（leaf-prover 需 registry 工件 +
//!   19.4GB；递归树同；终证腿需 scarb 2.18）——真 K 由 bench-recursion 在
//!   服务器跑，跑前先以一条真实 leaf 产物做互操作冒烟。
//!
//! # 进程纪律（内存上界的执行面）
//!
//! 每步一个子进程（叶 19.4GB / 折叠 7.4GB 必须不同时驻留，budget.rs 锚点）；
//! 步骤间只传文件（leaf 输入 JSON / registry / 根三件套 output），进程退出即
//! 释放峰值内存。

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::budget::{check_step, Step};
use crate::chain::{FoldPlan, ROOT_OUTPUT_WORDS};
use crate::envelope::{LeafProofEnvelope, PackedNode};

/// 叶证明后端。
pub trait LeafProver {
    /// 出一叶证明信封（mock：即时；cli：阻塞子进程）。
    ///
    /// # Errors
    /// 后端失败（mock 不失败；cli 见 [`CliBackend::prove_leaf`]）。
    fn prove_leaf(&self, preimage: &[groth16_wrap::felt::Felt252], work_dir: &Path)
        -> Result<LeafProofEnvelope>;
}

/// 折叠后端。
pub trait TreeFolder {
    /// 折叠整棵树：返回根公开输出词（终证语句的见证）与 packed 树。
    ///
    /// # Errors
    /// 后端失败。
    fn fold_tree(
        &self,
        leaves: &[LeafProofEnvelope],
        plan: &FoldPlan,
        work_dir: &Path,
    ) -> Result<([u32; ROOT_OUTPUT_WORDS], PackedNode)>;
}

/// 确定性 Mock 后端（测试/bench 默认）。
///
/// 叶 circuit_hash/preprocessed_root 取自 preimage 首词派生的确定性值（格式合规
/// 即可，mock 不承载 STARK 真伪——那是 fact-verify 的职责）；内部节点折叠用
/// blake2s(左词 ‖ 右词) 的**测试替身**（真实 digest 在电路内计算，见模块注释）。
#[derive(Debug, Clone, Copy, Default)]
pub struct MockBackend;

impl LeafProver for MockBackend {
    fn prove_leaf(
        &self,
        preimage: &[groth16_wrap::felt::Felt252],
        _work_dir: &Path,
    ) -> Result<LeafProofEnvelope> {
        // 确定性 circuit 标识：H1 词序取反做 preprocessed_root（可复现、格式合规）
        let h1 = crate::chain::leaf_output_words(preimage)?;
        let tag: [u32; 8] = std::array::from_fn(|i| h1[i].wrapping_add(i as u32));
        Ok(LeafProofEnvelope::from_preimage(tag, tag, "bW9jaw==", preimage))
    }
}

impl TreeFolder for MockBackend {
    fn fold_tree(
        &self,
        leaves: &[LeafProofEnvelope],
        plan: &FoldPlan,
        _work_dir: &Path,
    ) -> Result<([u32; ROOT_OUTPUT_WORDS], PackedNode)> {
        anyhow::ensure!(
            leaves.len() == plan.leaves,
            "leaves {} != plan.leaves {}",
            leaves.len(),
            plan.leaves
        );
        for l in leaves {
            l.output_words().context("mock fold: leaf output recompute")?;
        }
        // 测试替身折叠（真实链 = multiverifier 电路内 blake 门；fold.rs:135-137）：
        // 逐层两两折叠 blake2s(左词 ‖ 右词)，层数/步数与 FoldPlan 一致
        let mut level: Vec<([u32; ROOT_OUTPUT_WORDS], PackedNode)> = leaves
            .iter()
            .map(|l| {
                let words = l.output_words().expect("checked above");
                (words, PackedNode::leaf(l.proof.circuit_hash.0, l.output_preimage.clone()))
            })
            .collect();
        let mut layer = 1usize;
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len() / 2);
            for i in 0..level.len() / 2 {
                next.push(mock_fold_pair(&level[2 * i], &level[2 * i + 1], layer));
            }
            level = next;
            layer += 1;
        }
        let layers_used = if plan.leaves == 1 { 1 } else { layer - 1 };
        anyhow::ensure!(
            layers_used == plan.n_layers(),
            "mock fold used {layers_used} layers, plan has {}",
            plan.n_layers()
        );
        // L=1：单叶自折叠根（fold.rs:114-120 同形——同一信封进两个槽位）
        let (w, node) = level.pop().ok_or_else(|| anyhow!("no root"))?;
        if plan.leaves == 1 {
            let root_node = match node {
                PackedNode::Composite { circuit_hash, subtasks } => PackedNode::Composite {
                    circuit_hash,
                    subtasks: vec![subtasks[0].clone(), subtasks[0].clone()],
                },
                other => PackedNode::Composite {
                    circuit_hash: [1; 8],
                    subtasks: vec![other.clone(), other],
                },
            };
            return Ok((w, root_node));
        }
        Ok((w, node))
    }
}

/// Mock 折叠一对：digest = blake2s(左词 ‖ 右词) 的 8 个 LE 词（测试替身，非电路内
/// 真实公式；见模块注释的边界声明）。
fn mock_fold_pair(
    left: &([u32; ROOT_OUTPUT_WORDS], PackedNode),
    right: &([u32; ROOT_OUTPUT_WORDS], PackedNode),
    layer: usize,
) -> ([u32; ROOT_OUTPUT_WORDS], PackedNode) {
    let mut bytes = Vec::with_capacity(64);
    for w in left.0.iter().chain(right.0.iter()) {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    use blake2::Digest as _;
    let d: [u8; 32] = blake2::Blake2s256::digest(&bytes).into();
    let words: [u32; 8] = std::array::from_fn(|i| {
        u32::from_le_bytes(d[i * 4..i * 4 + 4].try_into().expect("4B"))
    });
    (
        words,
        PackedNode::Composite {
            circuit_hash: [layer as u32; 8],
            subtasks: vec![left.1.clone(), right.1.clone()],
        },
    )
}

/// 真实链 CLI 后端（服务器编排；参数面与 vendored CLI 逐旗核对）。
///
/// CLI 契约出处：
/// - leaf-prover：`--program <bootloader> --program_input <任务清单>
///   --circuit_registry_json <registry>`（架构 §0②；leaf_prover/src/main.rs:22-38）；
/// - 递归树：`--program_input <leaves manifest> --proof_path <out>
///   --program_output <out> --packed_output_path <out> --circuit_registry_json
///   <registry>`（third_party/proving crates/stwo_run_and_prove_recursive_tree/
///   src/main.rs:26-57 本轮实读）。
#[derive(Debug, Clone)]
pub struct CliBackend {
    /// leaf-prover 可执行文件路径。
    pub leaf_prover_bin: PathBuf,
    /// stwo_run_and_prove_recursive_tree 可执行文件路径。
    pub recursive_tree_bin: PathBuf,
    /// bootloader 编译产物（叶任务程序）。
    pub bootloader_path: PathBuf,
    /// circuit registry JSON（definition/prover params/FRI config 的合订工件）。
    pub circuit_registry_json: PathBuf,
    /// 本机可用内存上限（字节；喂给 [`check_step`] 的闸门值）。
    pub available_bytes: u64,
}

impl CliBackend {
    /// 叶证明：内存闸门 → 装配 argv → 阻塞子进程 → 读回信封。
    ///
    /// # Errors
    /// 闸门拒绝 / 可执行文件缺失 / 非零退出 / 信封解析失败。
    pub fn prove_leaf(
        &self,
        preimage: &[groth16_wrap::felt::Felt252],
        work_dir: &Path,
    ) -> Result<LeafProofEnvelope> {
        check_step(Step::LeafProve, self.available_bytes).context("leaf prove 内存闸门")?;
        std::fs::create_dir_all(work_dir)?;
        let input = LeafProofEnvelope::from_preimage([0; 8], [0; 8], "", preimage);
        let task_path = work_dir.join("leaf_task_input.json");
        std::fs::write(&task_path, serde_json::to_vec_pretty(&input)?)?;
        let out_path = work_dir.join("leaf_proof.json");
        let mut cmd = Command::new(&self.leaf_prover_bin);
        cmd.arg("--program").arg(&self.bootloader_path)
            .arg("--program_input").arg(&task_path)
            .arg("--circuit_registry_json").arg(&self.circuit_registry_json);
        run_checked(&mut cmd).context("leaf-prover 子进程")?;
        let json = std::fs::read_to_string(&out_path)
            .with_context(|| format!("leaf 产物缺失：{}", out_path.display()))?;
        Ok(serde_json::from_str(&json)?)
    }

    /// 折叠整树：leaves manifest → 递归树二进制 → 读根三件套。
    ///
    /// # Errors
    /// 闸门拒绝 / 子进程失败 / 产物缺失或解析失败。
    pub fn fold_tree(
        &self,
        leaves: &[LeafProofEnvelope],
        plan: &FoldPlan,
        work_dir: &Path,
    ) -> Result<([u32; ROOT_OUTPUT_WORDS], PackedNode)> {
        check_step(Step::Fold, self.available_bytes).context("fold 内存闸门")?;
        anyhow::ensure!(leaves.len() == plan.leaves, "leaves/plan 不一致");
        std::fs::create_dir_all(work_dir)?;
        // manifest：{"leaves": ["<path>", …]}（leaf_io.rs:84-101 load_leaves 同形）
        let mut leaf_paths = Vec::with_capacity(leaves.len());
        for (i, leaf) in leaves.iter().enumerate() {
            let p = work_dir.join(format!("leaf_{i}.json"));
            std::fs::write(&p, serde_json::to_vec(leaf)?)?;
            leaf_paths.push(p.display().to_string());
        }
        let manifest_path = work_dir.join("leaves_manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_string(&serde_json::json!({ "leaves": leaf_paths }))?,
        )?;
        let proof_path = work_dir.join("root_proof.json");
        let output_path = work_dir.join("root_output.json");
        let packed_path = work_dir.join("packed_output.json");
        let mut cmd = Command::new(&self.recursive_tree_bin);
        cmd.arg("--program_input").arg(&manifest_path)
            .arg("--circuit_registry_json").arg(&self.circuit_registry_json)
            .arg("--proof_path").arg(&proof_path)
            .arg("--program_output").arg(&output_path)
            .arg("--packed_output_path").arg(&packed_path);
        run_checked(&mut cmd).context("recursive tree 子进程")?;
        let words: [u32; ROOT_OUTPUT_WORDS] = serde_json::from_str(
            &std::fs::read_to_string(&output_path)
                .with_context(|| format!("根输出缺失：{}", output_path.display()))?,
        )?;
        let packed: PackedNode = serde_json::from_str(
            &std::fs::read_to_string(&packed_path)
                .with_context(|| format!("packed 树缺失：{}", packed_path.display()))?,
        )?;
        packed.validate_shape().context("packed 树形状")?;
        Ok((words, packed))
    }

    /// CLI 面自检（不执行）：三个输入是否在位。
    ///
    /// # Errors
    /// 任一路径不存在。
    pub fn check_inputs(&self) -> Result<()> {
        for p in [&self.leaf_prover_bin, &self.recursive_tree_bin, &self.bootloader_path, &self.circuit_registry_json] {
            anyhow::ensure!(p.exists(), "missing cli input: {}", p.display());
        }
        Ok(())
    }
}

fn run_checked(cmd: &mut Command) -> Result<()> {
    let status = cmd.status().with_context(|| format!("spawn {:?}", cmd.get_program()))?;
    anyhow::ensure!(status.success(), "command {:?} failed: {status}", cmd.get_program());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use groth16_wrap::felt::{felt_from_hex, Felt252};
    use groth16_wrap::golden;

    fn sample_preimage(n_segments: usize) -> Vec<Felt252> {
        let mut pre = vec![felt_from_hex(golden::GOLDEN_PROGRAM_HASH).unwrap()];
        for i in 0..n_segments {
            pre.push(Felt252::from(15u64));
            pre.push(Felt252::from(0x5350324d5f4f4bu64));
            pre.push(Felt252::from(i as u64));
        }
        pre
    }

    /// Mock 叶：确定性（同输入两次逐字节一致）+ H1 与 chain 层一致。
    #[test]
    fn mock_leaf_deterministic() {
        let pre = sample_preimage(2);
        let a = MockBackend.prove_leaf(&pre, Path::new("/tmp")).unwrap();
        let b = MockBackend.prove_leaf(&pre, Path::new("/tmp")).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.output_words().unwrap(), crate::chain::leaf_output_words(&pre).unwrap());
    }

    /// Mock 折叠：L=2/L=4 形状正确、根输出确定性、packed 树结构过闸。
    #[test]
    fn mock_fold_shapes() {
        for l in [1usize, 2, 4] {
            let leaves: Vec<LeafProofEnvelope> =
                (0..l).map(|i| MockBackend.prove_leaf(&sample_preimage(i + 1), Path::new("/tmp")).unwrap()).collect();
            let plan = FoldPlan::new(l).unwrap();
            let (words, packed) = MockBackend.fold_tree(&leaves, &plan, Path::new("/tmp")).unwrap();
            packed.validate_shape().unwrap();
            assert_eq!(words.len(), 8);
            // 确定性
            let leaves2 = leaves.clone();
            let (words2, _) = MockBackend.fold_tree(&leaves2, &plan, Path::new("/tmp")).unwrap();
            assert_eq!(words, words2, "mock 折叠必须确定性（L={l}）");
        }
    }

    /// CliBackend 参数装配面：缺输入 fail-closed；argv 关键旗在位。
    #[test]
    fn cli_backend_fail_closed_on_missing_inputs() {
        let be = CliBackend {
            leaf_prover_bin: PathBuf::from("/nonexistent/leaf-prover"),
            recursive_tree_bin: PathBuf::from("/nonexistent/tree"),
            bootloader_path: PathBuf::from("/nonexistent/bootloader.json"),
            circuit_registry_json: PathBuf::from("/nonexistent/registry.json"),
            available_bytes: 0,
        };
        assert!(be.check_inputs().is_err());
        // 叶闸门：available=0 必拒（实测锚点 19.4GB）
        let pre = sample_preimage(1);
        let err = be
            .prove_leaf(&pre, std::env::temp_dir().join("stark-recursion-test").as_path())
            .unwrap_err();
        assert!(format!("{err:#}").contains("内存闸门"), "必须先过内存闸门: {err:#}");
    }
}
