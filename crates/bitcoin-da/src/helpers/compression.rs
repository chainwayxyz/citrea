use std::io::Write;

#[cfg(feature = "native")]
pub fn compress_blob(blob: &[u8]) -> Vec<u8> {
    use brotli::CompressorWriter;
    let mut writer = CompressorWriter::new(Vec::new(), 4096, 11, 22);
    writer.write_all(blob).unwrap();
    writer.into_inner()
}

pub fn decompress_blob(blob: &[u8]) -> Vec<u8> {
    use brotli::DecompressorWriter;
    let mut writer = DecompressorWriter::new(Vec::new(), 4096);
    writer.write_all(blob).unwrap();
    writer.into_inner().expect("decompression failed")
}
