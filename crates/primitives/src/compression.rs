use std::io::{self, Write};

pub fn compress_blob(blob: &[u8]) -> Result<Vec<u8>, io::Error> {
    use brotli::CompressorWriter;
    let mut writer = CompressorWriter::new(Vec::new(), 4096, 11, 22);
    writer.write_all(blob)?;
    Ok(writer.into_inner())
}

pub fn decompress_blob(blob: &[u8]) -> Result<Vec<u8>, io::Error> {
    use brotli::DecompressorWriter;
    let mut writer = DecompressorWriter::new(Vec::new(), 4096);
    writer.write_all(blob)?;
    match writer.into_inner() {
        Ok(result) => Ok(result),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Brotli decompression failure",
        )),
    }
}
