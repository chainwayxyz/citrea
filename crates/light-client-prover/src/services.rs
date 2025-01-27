use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use citrea_common::{LightClientProverConfig, RollupPublicKeys, RunnerConfig};
use jsonrpsee::RpcModule;
use sov_db::ledger_db::{LightClientProverLedgerOps, SharedLedgerOps};
use sov_db::mmr_db::MmrDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_modules_api::{SpecId, Zkvm};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::ZkvmHost;
use sov_stf_runner::ProverService;

use crate::da_block_handler::L1BlockHandler;
use crate::rpc;
use crate::runner::CitreaLightClientProver;

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn build_services<Vm, Da, Ps, DB>(
    prover_config: LightClientProverConfig,
    runner_config: RunnerConfig,
    rocksdb_config: &RocksdbConfig,
    ledger_db: DB,
    da_service: Arc<Da>,
    prover_service: Arc<Ps>,
    public_keys: RollupPublicKeys,
    batch_prover_code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
    light_client_prover_code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
    light_client_prover_elfs: HashMap<SpecId, Vec<u8>>,
    rpc_module: RpcModule<()>,
) -> Result<(
    CitreaLightClientProver,
    L1BlockHandler<Vm, Da, Ps, DB>,
    RpcModule<()>,
)>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    Ps: ProverService<DaService = Da>,
    DB: LightClientProverLedgerOps + SharedLedgerOps + Clone + 'static,
{
    let rpc_context = rpc::create_rpc_context(ledger_db.clone());
    let rpc_module = rpc::register_rpc_methods(rpc_module, rpc_context)?;

    let mmr_db = MmrDB::new(rocksdb_config)?;
    let l1_block_handler = L1BlockHandler::new(
        prover_config,
        prover_service,
        ledger_db,
        da_service,
        public_keys.prover_da_pub_key,
        batch_prover_code_commitments,
        light_client_prover_code_commitments,
        light_client_prover_elfs,
        mmr_db,
    );

    let prover = CitreaLightClientProver::new(runner_config)?;

    Ok((prover, l1_block_handler, rpc_module))
}
