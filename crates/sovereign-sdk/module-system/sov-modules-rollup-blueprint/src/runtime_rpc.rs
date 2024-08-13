use sov_db::ledger_db::LedgerDB;
use sov_modules_api::{Context, Spec};
use sov_modules_stf_blueprint::{Runtime as RuntimeTrait, SequencerOutcome, TxEffect};
use sov_rollup_interface::services::da::DaService;

/// Register rollup's default rpc methods.
pub fn register_rpc<RT, C, Da>(
    storage: &<C as Spec>::Storage,
    ledger_db: &LedgerDB,
    _da_service: &Da,
    _sequencer: C::Address,
) -> Result<jsonrpsee::RpcModule<()>, anyhow::Error>
where
    RT: RuntimeTrait<C, <Da as DaService>::Spec> + Send + Sync + 'static,
    C: Context,
    Da: DaService,
{
    // runtime rpc.
    let mut rpc_methods = RT::rpc_methods(storage.clone());

    // ledger rpc.
    {
        rpc_methods.merge(sov_ledger_rpc::server::rpc_module::<
            LedgerDB,
            SequencerOutcome<<C as Spec>::Address>,
            TxEffect,
        >(ledger_db.clone())?)?;
    }

    Ok(rpc_methods)
}
