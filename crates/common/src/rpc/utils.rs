use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::ErrorObjectOwned;

pub fn internal_rpc_error(msg: impl ToString) -> ErrorObjectOwned {
    let data = Some(msg.to_string());
    ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG, data)
}
