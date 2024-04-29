pub(crate) fn get_db_extension() -> String {
    let thread = std::thread::current();
    let mut thread_name = format!("_{}", thread.name().unwrap_or("unnamed"));
    if thread_name == "tokio-runtime-worker" {
        thread_name = "".to_string();
    }
    thread_name
        .split(":")
        .collect::<Vec<&str>>()
        .last()
        .unwrap_or(&"unnamed")
        .to_string()
}

#[test]
fn test_get_db_extension() {
    let a = get_db_extension();
    assert_eq!(a, "_test_get_db_extension");
}
