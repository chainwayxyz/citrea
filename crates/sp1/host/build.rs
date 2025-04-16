use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    let args = BuildArgs {
        #[cfg(feature = "testing")]
        features: vec!["testing".to_string()],
        ..Default::default()
    };

    build_program_with_args("../../../guests/sp1/batch-proof-bitcoin", args);
}
