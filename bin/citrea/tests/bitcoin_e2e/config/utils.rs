use std::path::Path;

use serde::Serialize;

pub fn config_to_file<C, P>(config: &C, path: &P) -> std::io::Result<()>
where
    C: Serialize,
    P: AsRef<Path>,
{
    let toml =
        toml::to_string(config).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(path, toml)?;
    Ok(())
}
