/// Derives the [`DispatchCall`] trait for the underlying
/// type.
#[cfg(feature = "macros")]
pub use sov_modules_macros::DispatchCall;
/// Implements ForkCodec trait. Requires the type to be enum.
#[cfg(feature = "macros")]
pub use sov_modules_macros::ForkCodec;
/// Derives the [`Genesis`](trait.Genesis.html) trait for the underlying runtime
/// `struct`.
#[cfg(feature = "macros")]
pub use sov_modules_macros::Genesis;
/// Derives the [`ModuleInfo`] trait for the underlying `struct`, giving full access to kernel functionality
#[cfg(feature = "macros")]
pub use sov_modules_macros::KernelModuleInfo;
#[cfg(feature = "macros")]
pub use sov_modules_macros::MessageCodec;
/// Derives the [`ModuleCallJsonSchema`](trait.ModuleCallJsonSchema.html) trait for
/// the underlying type.
///
/// ## Example
///
/// ```
/// use std::marker::PhantomData;
///
/// use sov_modules_api::{WorkingSet,Error, CallResponse, Context, Module, ModuleInfo, ModuleCallJsonSchema, StateMap};
/// use sov_modules_api::default_context::ZkDefaultContext;
///
/// #[derive(ModuleInfo, ModuleCallJsonSchema)]
/// struct TestModule<C: Context> {
///     #[address]
///     admin: C::Address,
///
///     #[state]
///     pub state_map: StateMap<String, u32>,
/// }
///
/// impl<C: Context> Module for TestModule<C> {
///     type Context = C;
///     type Config = PhantomData<C>;
///     type CallMessage = ();
///     
///     fn call(
///        &mut self,
///        _msg: Self::CallMessage,
///        _context: &Self::Context,
///        _working_set: &mut WorkingSet<C::Storage>,
///     ) -> Result<CallResponse, Error> {
///        Ok(CallResponse {})
///     }
/// }
///
/// println!("JSON Schema: {}", TestModule::<ZkDefaultContext>::json_schema());
/// ```
#[cfg(feature = "macros")]
pub use sov_modules_macros::ModuleCallJsonSchema;
/// Derives the [`ModuleInfo`] trait for the underlying `struct`.
///
/// The underlying type must respect the following conditions, or compilation
/// will fail:
/// - It must be a named `struct`. Tuple `struct`s, `enum`s, and others are
///   not supported.
/// - It must have *exactly one* field with the `#[address]` attribute. This field
///   represents the **module address**.
/// - All other fields must have either the `#[state]` or `#[module]` attribute.
///   - `#[state]` is used for state members.
///   - `#[module]` is used for module members.
///
/// In addition to implementing [`ModuleInfo`], this macro will
/// also generate so-called "prefix" methods.
///
/// ## Example
///
/// ```
/// use sov_modules_api::{Context, ModuleInfo, StateMap};
///
/// #[derive(ModuleInfo)]
/// struct TestModule<C: Context> {
///     #[address]
///     admin: C::Address,
///
///     #[state]
///     pub state_map: StateMap<String, u32>,
/// }
///
/// // You can then get the prefix of `state_map` like this:
/// fn get_prefix<C: Context>(some_storage: C::Storage) {
///     let test_struct = TestModule::<C>::default();
///     let prefix1 = test_struct.state_map.prefix();
/// }
/// ```
#[cfg(feature = "macros")]
pub use sov_modules_macros::ModuleInfo;

/// Procedural macros to assist with creating new modules.
#[cfg(feature = "macros")]
pub mod macros {
    /// Sets the value of a constant at compile time by reading from the Manifest file.
    pub use sov_modules_macros::config_constant;
    /// The macro exposes RPC endpoints from all modules in the runtime.
    /// It gets storage from the Context generic
    /// and utilizes output of [`#[rpc_gen]`] macro to generate RPC methods.
    ///
    /// It has limitations:
    ///   - First type generic attribute must have bound to [`Context`](sov_modules_core::Context) trait
    ///   - All generic attributes must own the data, thus have bound `'static`
    #[cfg(feature = "native")]
    pub use sov_modules_macros::expose_rpc;
    #[cfg(feature = "native")]
    pub use sov_modules_macros::rpc_gen;
    /// Derives a custom [`Default`] implementation for the underlying type.
    /// We decided to implement a custom macro DefaultRuntime that would implement a custom Default
    /// trait for the Runtime because the stdlib implementation of the default trait imposes the generic
    /// arguments to have the Default trait, which is not needed in our case.
    pub use sov_modules_macros::DefaultRuntime;
}
