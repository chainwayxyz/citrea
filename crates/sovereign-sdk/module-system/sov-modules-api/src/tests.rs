use sov_keys::default_signature::private_key::DefaultPrivateKey;
use sov_keys::{PrivateKey, Signature};
use sov_modules_core::Address;

use crate::default_context::DefaultContext;
use crate::ModuleInfo;

#[test]
fn test_account_bech32m_display() {
    let expected_addr: Vec<u8> = (1..=32).collect();
    let account = crate::AddressBech32::try_from(expected_addr.as_slice()).unwrap();
    assert_eq!(
        account.to_string(),
        "sov1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqqsn6hm"
    );
}

struct Module {
    address: Address,
    dependencies: Vec<Address>,
}

impl crate::ModuleInfo for Module {
    type Context = DefaultContext;

    fn address(&self) -> &<Self::Context as crate::Spec>::Address {
        &self.address
    }

    fn prefix(&self) -> crate::ModulePrefix {
        crate::ModulePrefix::new_module(module_path!(), "Module")
    }

    fn dependencies(&self) -> Vec<&<Self::Context as crate::Spec>::Address> {
        self.dependencies.iter().collect()
    }
}

#[test]
fn test_sorting_modules() {
    let module_a = Module {
        address: Address::from([1; 32]),
        dependencies: vec![],
    };
    let module_b = Module {
        address: Address::from([2; 32]),
        dependencies: vec![module_a.address],
    };
    let module_c = Module {
        address: Address::from([3; 32]),
        dependencies: vec![module_a.address, module_b.address],
    };

    let modules: Vec<(&dyn ModuleInfo<Context = DefaultContext>, i32)> =
        vec![(&module_b, 2), (&module_c, 3), (&module_a, 1)];

    let sorted_modules = crate::sort_values_by_modules_dependencies(modules).unwrap();

    assert_eq!(vec![1, 2, 3], sorted_modules);
}

#[test]
fn test_sorting_modules_missing_module() {
    let module_a_address = Address::from([1; 32]);
    let module_b = Module {
        address: Address::from([2; 32]),
        dependencies: vec![module_a_address],
    };
    let module_c = Module {
        address: Address::from([3; 32]),
        dependencies: vec![module_a_address, module_b.address],
    };

    let modules: Vec<(&dyn ModuleInfo<Context = DefaultContext>, i32)> =
        vec![(&module_b, 2), (&module_c, 3)];

    let sorted_modules = crate::sort_values_by_modules_dependencies(modules);

    assert!(sorted_modules.is_err());
    let error_string = sorted_modules.err().unwrap().to_string();
    assert_eq!("Module not found: AddressBech32 { value: \"sov1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs259tk3\" }", error_string);
}

#[test]
fn test_sorting_modules_cycle() {
    let module_e_address = Address::from([5; 32]);
    let module_a = Module {
        address: Address::from([1; 32]),
        dependencies: vec![],
    };
    let module_b = Module {
        address: Address::from([2; 32]),
        dependencies: vec![module_a.address],
    };
    let module_d = Module {
        address: Address::from([4; 32]),
        dependencies: vec![module_e_address],
    };
    let module_e = Module {
        address: module_e_address,
        dependencies: vec![module_a.address, module_d.address],
    };

    let modules: Vec<(&dyn ModuleInfo<Context = DefaultContext>, i32)> = vec![
        (&module_b, 2),
        (&module_d, 3),
        (&module_a, 1),
        (&module_e, 4),
    ];

    let sorted_modules = crate::sort_values_by_modules_dependencies(modules);

    assert!(sorted_modules.is_err());
    let error_string = sorted_modules.err().unwrap().to_string();
    assert_eq!("Cyclic dependency of length 2 detected: [AddressBech32 { value: \"sov1qszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqnu4g3u\" }, AddressBech32 { value: \"sov1q5zs2pg9q5zs2pg9q5zs2pg9q5zs2pg9q5zs2pg9q5zs2pg9q5zskwvj87\" }]", error_string);
}

#[test]
fn test_sorting_modules_duplicate() {
    let module_a = Module {
        address: Address::from([1; 32]),
        dependencies: vec![],
    };
    let module_b = Module {
        address: Address::from([2; 32]),
        dependencies: vec![module_a.address],
    };
    let module_a2 = Module {
        address: Address::from([1; 32]),
        dependencies: vec![],
    };

    let modules: Vec<(&dyn ModuleInfo<Context = DefaultContext>, u32)> =
        vec![(&module_b, 3), (&module_a, 1), (&module_a2, 2)];

    let sorted_modules = crate::sort_values_by_modules_dependencies(modules);

    assert!(sorted_modules.is_err());
    let error_string = sorted_modules.err().unwrap().to_string();
    assert_eq!("Duplicate module address! Only one instance of each module is allowed in a given runtime. Module with address sov1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs259tk3 is duplicated", error_string);
}

#[test]
fn test_default_signature_roundtrip() {
    let key = DefaultPrivateKey::generate();
    let msg = b"hello, world";
    let sig = key.sign(msg);
    sig.verify(&key.pub_key(), msg)
        .expect("Roundtrip verification failed");
}
