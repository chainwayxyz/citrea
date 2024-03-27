## Citrea STF

This is the State Transition Function crate for the Citrea rollup.

It's been built on various Sovereign SDK components such as `sov_modules_api`, `sov-state`, `sov_modules_stf_blueprint` (check `Sovereign-SDK` folder for more details).

Through applying transaction/blob/confirmation hooks (see `hooks_impl.rs`), it runs the rollup via the `Runtime`.
