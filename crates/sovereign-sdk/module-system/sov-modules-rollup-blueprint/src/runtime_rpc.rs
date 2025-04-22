use citrea_common::RpcConfig;
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::Spec;
use sov_modules_stf_blueprint::Runtime as RuntimeTrait;
use sov_prover_storage_manager::ProverStorage;
use sov_rollup_interface::services::da::DaService;

/// Register rollup's default rpc methods.
pub fn register_rpc<Da, RT>(
    storage: ProverStorage,
    ledger_db: &LedgerDB,
    _sequencer: <DefaultContext as Spec>::Address,
    rpc_config: RpcConfig,
) -> Result<jsonrpsee::RpcModule<()>, anyhow::Error>
where
    Da: DaService,
    RT: RuntimeTrait<DefaultContext, <Da as DaService>::Spec> + Send + Sync + 'static,
{
    // runtime rpc.
    let mut rpc_methods = RT::rpc_methods(storage);

    // ledger rpc.
    {
        rpc_methods.merge(sov_ledger_rpc::server::create_rpc_module::<LedgerDB>(
            ledger_db.clone(),
            rpc_config.into(),
        ))?;
    }

    Ok(rpc_methods)
}
