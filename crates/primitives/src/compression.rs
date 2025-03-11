use anyhow::anyhow;
use std::io::Write;

pub fn compress_blob(blob: &[u8]) -> anyhow::Result<Vec<u8>> {
    use brotli::CompressorWriter;
    let mut writer = CompressorWriter::new(Vec::new(), 4096, 11, 22);
    writer.write_all(blob)?;
    Ok(writer.into_inner())
}

pub fn decompress_blob(blob: &[u8]) -> anyhow::Result<Vec<u8>> {
    use brotli::DecompressorWriter;
    let mut writer = DecompressorWriter::new(Vec::new(), 4096);
    writer.write_all(blob)?;
    writer
        .into_inner()
        .map_err(|e| anyhow!("decompression failed {e:?}"))
}
