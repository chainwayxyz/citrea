//! Runtime call message definitions.

use borsh::io;
use sov_rollup_interface::spec::SpecId;

use crate::common::ModuleError;
use crate::module::{CallResponse, Context, Spec};
use crate::storage::WorkingSet;

/// A trait that needs to be implemented for any call message.
pub trait DispatchCall: Send + Sync {
    /// The context of the call
    type Context: Context;

    /// The concrete type that will decode into the call message of the module.
    type Decodable: Send + Sync;

    /// Decodes serialized call message
    fn decode_call(serialized_message: &[u8]) -> Result<Self::Decodable, io::Error>;

    /// Dispatches a call message to the appropriate module.
    fn dispatch_call(
        &self,
        message: Self::Decodable,
        working_set: &mut WorkingSet<Self::Context>,
        current_spec: SpecId,
        context: &Self::Context,
    ) -> Result<CallResponse, ModuleError>;

    /// Returns an address of the dispatched module.
    fn module_address(&self, message: &Self::Decodable) -> &<Self::Context as Spec>::Address;
}
