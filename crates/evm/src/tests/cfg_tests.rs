use revm::primitives::{CfgEnvWithHandlerCfg, SpecId};

use crate::call::{get_cfg_env, get_spec_id};
use crate::evm::primitive_types::BlockEnv;
use crate::evm::EvmChainConfig;
use crate::DEFAULT_CHAIN_ID;

#[test]
fn cfg_test() {
    let block_env = BlockEnv {
        number: 10,
        ..Default::default()
    };

    let cfg = EvmChainConfig {
        limit_contract_code_size: Some(100),
        spec: vec![(0, SpecId::SHANGHAI)].into_iter().collect(),
        ..Default::default()
    };

    let cfg_env = get_cfg_env(&block_env, cfg);

    let mut expected_cfg_env =
        CfgEnvWithHandlerCfg::new_with_spec_id(Default::default(), SpecId::SHANGHAI);
    expected_cfg_env.chain_id = DEFAULT_CHAIN_ID;
    expected_cfg_env.limit_contract_code_size = Some(100);

    assert_eq!(cfg_env, expected_cfg_env,);
}

#[test]
fn spec_id_lookup() {
    let spec = vec![
        (0, SpecId::CONSTANTINOPLE),
        (10, SpecId::BERLIN),
        (20, SpecId::LONDON),
    ];

    assert_eq!(get_spec_id(spec.clone(), 0), SpecId::CONSTANTINOPLE);
    assert_eq!(get_spec_id(spec.clone(), 5), SpecId::CONSTANTINOPLE);
    assert_eq!(get_spec_id(spec.clone(), 10), SpecId::BERLIN);
    assert_eq!(get_spec_id(spec.clone(), 15), SpecId::BERLIN);
    assert_eq!(get_spec_id(spec.clone(), 20), SpecId::LONDON);
    assert_eq!(get_spec_id(spec, 25), SpecId::LONDON);
}
