//! Trace 生成器 — 把业务输入转为 Stwo trace。
//!
//! ## 设计
//!
//! 每个方法 AIR 配套一个 trace 生成函数，直接从 Rust 业务语义构造 trace
//! （**不经 RV32IM 执行**），这就是自定义电路 vs zkVM 的核心区别。
//!
//! ## 流程
//!
//! 1. 业务层执行 `apply_*`，记录 pre/post state
//! 2. 调用 [`compute_state_root`] 得到 `pre_state_root` / `post_state_root`
//! 3. 调用对应方法的 trace 生成器构造 `MethodTrace`
//! 4. 传给 [`crate::prover`] 生成 Stwo proof
//!
//! ## 通用辅助
//!
//! [`generic_trace`] 提供通用 trace 构造函数，避免为每个方法重复模板代码：
//! - [`gen_method_trace`] — 从单行 active + padding 构造完整 trace

use stwo::core::fields::m31::M31;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::NaturalOrder;
use stwo::prover::poly::circle::CircleEvaluation;

use crate::airs::common::ZERO;
use crate::error::{TexasAirError, TexasAirResult};

pub mod generic_trace;

/// 业务方法的 trace 数据结构。
#[derive(Debug, Clone)]
pub struct MethodTrace {
    /// log2(行数)。
    pub log_size: u32,
    /// 列数。
    pub num_columns: usize,
    /// 列主序存储的 M31 数据（每列连续）。
    pub cols: Vec<Vec<M31>>,
}

impl MethodTrace {
    /// 构造空 trace。
    #[must_use]
    pub fn new(log_size: u32, num_columns: usize) -> Self {
        let rows = 1usize << log_size;
        Self {
            log_size,
            num_columns,
            cols: vec![vec![ZERO; rows]; num_columns],
        }
    }

    /// Column-wise constructor taking fully materialized columns.
    ///
    /// Unlike [`MethodTrace::new`] this never zero-fills the matrix: every
    /// column must already carry exactly `1 << log_size` values (callers that
    /// leave columns for a later fill pass should pass empty vectors and
    /// overwrite them wholesale, e.g. via [`MethodTrace::set_column`]).
    #[must_use]
    pub fn from_columns(log_size: u32, cols: Vec<Vec<M31>>) -> Self {
        let num_columns = cols.len();
        Self {
            log_size,
            num_columns,
            cols,
        }
    }

    /// Replace one column wholesale, growing it to the full domain height
    /// with `value` when the column is shorter (used by table-fill passes).
    pub fn set_column(&mut self, column_index: usize, column: Vec<M31>) {
        let rows = 1usize << self.log_size;
        let mut column = column;
        if column.len() < rows {
            column.resize(rows, ZERO);
        }
        self.cols[column_index] = column;
    }

    /// Allocate a zero-height trace skeleton with full-width capacity.
    ///
    /// Columns start empty (capacity `1 << log_size`); callers materialize
    /// them column-by-column before [`MethodTrace::to_evaluations`].
    #[must_use]
    pub fn new_unfilled(log_size: u32, num_columns: usize) -> Self {
        let rows = 1usize << log_size;
        Self {
            log_size,
            num_columns,
            cols: (0..num_columns).map(|_| Vec::with_capacity(rows)).collect(),
        }
    }

    /// 写入一行数据（行索引 `row_idx`，列向量 `row`）。
    ///
    /// # Errors
    ///
    /// 当 `row.len() != num_columns` 或 `row_idx` 越界时返回错误。
    pub fn write_row(&mut self, row_idx: usize, row: &[M31]) -> TexasAirResult<()> {
        if row.len() != self.num_columns {
            return Err(TexasAirError::TraceGenError(format!(
                "row.len() = {} != num_columns = {}",
                row.len(),
                self.num_columns
            )));
        }
        let rows = 1usize << self.log_size;
        if row_idx >= rows {
            return Err(TexasAirError::TraceGenError(format!(
                "row_idx {row_idx} >= rows {rows}"
            )));
        }
        for (col_idx, &val) in row.iter().enumerate() {
            self.cols[col_idx][row_idx] = val;
        }
        Ok(())
    }

    /// Return row zero in column order.
    ///
    /// Single-step Texas AIRs replicate this business row over the complete
    /// trace domain. Verifier-side task reconstruction binds exactly this
    /// column vector through [`crate::public_inputs::TexasPublicInputs`].
    ///
    /// # Errors
    ///
    /// Returns [`TexasAirError::TraceGenError`] if the trace has no columns or
    /// a malformed empty column.
    pub fn first_row(&self) -> TexasAirResult<Vec<M31>> {
        if self.cols.is_empty() {
            return Err(TexasAirError::TraceGenError(
                "cannot bind an empty method trace".into(),
            ));
        }
        self.cols
            .iter()
            .enumerate()
            .map(|(column, values)| {
                values.first().copied().ok_or_else(|| {
                    TexasAirError::TraceGenError(format!(
                        "method trace column {column} has no rows"
                    ))
                })
            })
            .collect()
    }

    /// Padding 所有剩余行为 0。
    pub fn pad_zero(&mut self, from_row: usize) {
        let rows = 1usize << self.log_size;
        for col in &mut self.cols {
            for r in from_row..rows {
                col[r] = ZERO;
            }
        }
    }

    /// 把单步 active 行复制到整个 SIMD trace。
    ///
    /// # 参数
    /// - `active_row`: 业务行（复制到所有行）
    /// - `padding_row`: 仅用于兼容旧调用方并校验列宽；不会写入 trace
    ///
    /// # Errors
    ///
    /// 当行长度不匹配时返回错误。
    pub fn write_active_with_padding(
        &mut self,
        active_row: &[M31],
        padding_row: &[M31],
    ) -> TexasAirResult<()> {
        if padding_row.len() != self.num_columns {
            return Err(TexasAirError::TraceGenError(format!(
                "padding_row.len() = {} != num_columns = {}",
                padding_row.len(),
                self.num_columns
            )));
        }
        if active_row.len() != self.num_columns {
            return Err(TexasAirError::TraceGenError(format!(
                "active_row.len() = {} != num_columns = {}",
                active_row.len(),
                self.num_columns
            )));
        }
        // Column-wise fill: one memset-style pass per column instead of a
        // strided per-row element scatter.
        for (column, &value) in self.cols.iter_mut().zip(active_row) {
            column.fill(value);
        }
        Ok(())
    }

    /// 转换为 Stwo `CircleEvaluation` 列表（用于 commitment）。
    ///
    /// 每列独立构造 evaluation，先以 `NaturalOrder` 创建，
    /// 再通过 `.bit_reverse()` 转换为 `BitReversedOrder`（Stwo commitment 要求）。
    #[must_use]
    pub fn to_evaluations(&self) -> Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> {
        let domain = CanonicCoset::new(self.log_size).circle_domain();
        self.cols
            .iter()
            .map(|col| {
                let base_col = BaseColumn::from_cpu(col.as_slice());
                // 先以 NaturalOrder 构造，再 bit_reverse → BitReversedOrder
                CircleEvaluation::<SimdBackend, M31, NaturalOrder>::new(domain, base_col)
                    .bit_reverse()
            })
            .collect()
    }
}
