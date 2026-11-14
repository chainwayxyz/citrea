#[cfg(not(target_os = "zkvm"))]
include!(concat!(env!("OUT_DIR"), "/methods.rs"));
// Written by the light-client build script before it builds its guests.
#[cfg(target_os = "zkvm")]
include!("../../target/batch-proof-ids.rs");
