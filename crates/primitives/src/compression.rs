use std::cmp::min;
use std::io::{self, Read, Write};

use crate::MAX_DECOMPRESSED_BLOB_SIZE;

pub fn compress_blob(blob: &[u8]) -> Result<Vec<u8>, io::Error> {
    use brotli::CompressorWriter;
    let mut writer = CompressorWriter::new(Vec::new(), 4096, 11, 22);
    writer.write_all(blob)?;
    Ok(writer.into_inner())
}

pub fn decompress_blob(blob: &[u8]) -> Result<Vec<u8>, io::Error> {
    let mut reader = brotli::Decompressor::new(
        blob,
        4 * 1024, // 4kb buffer size
    );

    let mut buf = [0u8; 4096];

    let mut decompressed_data = Vec::with_capacity(min(blob.len() * 10 / 3, 1024 * 400)); // Knowing that on average brotli compresses our proofs by about 70%, we can preallocate dynamically with the compressed size in mind.

    loop {
        match reader.read(&mut buf) {
            Err(e) => {
                if let io::ErrorKind::Interrupted = e.kind() {
                    continue;
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Brotli decompression failure",
                ));
            }
            Ok(size) => {
                if size + decompressed_data.len() > MAX_DECOMPRESSED_BLOB_SIZE {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Decompressed data exceeds maximum allowed size of {MAX_DECOMPRESSED_BLOB_SIZE} bytes"
                        ),
                    ));
                }
                if size == 0 {
                    break;
                }
                decompressed_data.extend_from_slice(&buf[..size]);
            }
        }
    }

    Ok(decompressed_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_blob() {
        let blob = vec![0u8; 1024]; // 1KB blob
        let compressed_blob = compress_blob(&blob).expect("Compression failed");
        assert!(
            !compressed_blob.is_empty(),
            "Compressed blob should not be empty"
        );
    }

    #[test]
    fn test_decompress_blob() {
        let blob = vec![0u8; 1024]; // 1KB blob
        let compressed_blob = compress_blob(&blob).expect("Compression failed");
        let decompressed_blob = decompress_blob(&compressed_blob).expect("Decompression failed");
        assert_eq!(
            decompressed_blob, blob,
            "Decompressed blob should match original"
        );
    }

    #[test]
    fn test_decompress_exceeds_max_size() {
        let huge_blob = vec![0u8; MAX_DECOMPRESSED_BLOB_SIZE * 10]; // 10 times the max size
        let compressed_huge_blob = compress_blob(&huge_blob).expect("Compression failed");
        assert!(
            decompress_blob(&compressed_huge_blob).is_err(),
            "Should fail on exceeding max size"
        );

        let large_blob = vec![0u8; MAX_DECOMPRESSED_BLOB_SIZE + 1];
        let compressed_large_blob = compress_blob(&large_blob).expect("Compression failed");
        assert!(
            decompress_blob(&compressed_large_blob).is_err(),
            "Should fail on exceeding max size"
        );

        let limit_blob = vec![0u8; MAX_DECOMPRESSED_BLOB_SIZE];
        let compressed_limit_blob = compress_blob(&limit_blob).expect("Compression failed");
        let decompressed_limit_blob =
            decompress_blob(&compressed_limit_blob).expect("Decompression failed");
        assert_eq!(
            decompressed_limit_blob, limit_blob,
            "Decompressed blob should match original within size limit"
        );
    }
}
