use std::sync::Arc;

use sov_schema_db::test::TestField;
use sov_schema_db::transaction::DbTransaction;
use sov_schema_db::{define_schema, Schema, DB};

define_schema!(TestSchema1, TestField, TestField, "TestCF1");

type S = TestSchema1;

#[test]
fn transaction_lifecycle() {
    let db = Arc::new(DB::open_temp(
        "test-db-transaction",
        vec![S::COLUMN_FAMILY_NAME],
    ));

    let key = TestField(1);
    let value = TestField(1);

    let transaction_1 = DbTransaction::new(db.clone());
    assert_eq!(
        None,
        transaction_1.read::<S>(&key).unwrap(),
        "Incorrect value, should find nothing"
    );

    transaction_1.put::<S>(&key, &value).unwrap();
    assert_eq!(
        Some(value),
        transaction_1.read::<S>(&key).unwrap(),
        "Incorrect value, should be fetched from local cache"
    );
    db.write_schemas(transaction_1.into()).unwrap();

    // transaction 2: reads value from transaction 1, then deletes it
    let transaction_2 = DbTransaction::new(db.clone());
    assert_eq!(Some(value), transaction_2.read::<S>(&key).unwrap());
    transaction_2.delete::<S>(&key).unwrap();
    assert_eq!(None, transaction_2.read::<S>(&key).unwrap());
    db.write_schemas(transaction_2.into()).unwrap();

    // transaction 3: gets empty result value is in some previous transactions
    let transaction_3 = DbTransaction::new(db);
    assert_eq!(None, transaction_3.read::<S>(&key).unwrap());
}
