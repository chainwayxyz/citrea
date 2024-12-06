#![deny(missing_docs)]
//! The rollup capabilities module defines "capabilities" that rollup must
//! provide if they wish to use the standard app template.
//! If you don't want to provide these capabilities,
//! you can bypass the Sovereign module-system completely
//! and write a state transition function from scratch.
//! [See here for docs](https://github.com/Sovereign-Labs/sovereign-sdk/blob/nightly/examples/demo-stf/README.md)

use sov_rollup_interface::da::BlobReaderTrait;

/// Container type for mixing borrowed and owned blobs.
#[derive(Debug)]
pub enum BlobRefOrOwned<'a, B: BlobReaderTrait> {
    /// Mutable reference
    Ref(&'a mut B),
    /// Owned blob
    Owned(B),
}

impl<'a, B: BlobReaderTrait> AsRef<B> for BlobRefOrOwned<'a, B> {
    fn as_ref(&self) -> &B {
        match self {
            BlobRefOrOwned::Ref(r) => r,
            BlobRefOrOwned::Owned(blob) => blob,
        }
    }
}

impl<'a, B: BlobReaderTrait> BlobRefOrOwned<'a, B> {
    /// Convenience method to get mutable reference to the blob
    pub fn as_mut_ref(&mut self) -> &mut B {
        match self {
            BlobRefOrOwned::Ref(r) => r,
            BlobRefOrOwned::Owned(ref mut blob) => blob,
        }
    }
}

impl<'a, B: BlobReaderTrait> From<B> for BlobRefOrOwned<'a, B> {
    fn from(value: B) -> Self {
        BlobRefOrOwned::Owned(value)
    }
}

impl<'a, B: BlobReaderTrait> From<&'a mut B> for BlobRefOrOwned<'a, B> {
    fn from(value: &'a mut B) -> Self {
        BlobRefOrOwned::Ref(value)
    }
}
