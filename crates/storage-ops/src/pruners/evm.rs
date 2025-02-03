use citrea_evm::Evm;
use sov_modules_api::default_context::DefaultContext;
use tracing::debug;

/// Prune evm
pub(crate) fn prune_evm(up_to_block: u64) {
    debug!("Pruning EVM, up to L2 block {}", up_to_block);
    let _evm = Evm::<DefaultContext>::default();
    // unimplemented!()
}
