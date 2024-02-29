//! Gas unit definitions and implementations.

use core::fmt;

/// A gas unit that provides scalar conversion from complex, multi-dimensional types.
pub trait GasUnit: fmt::Debug + Clone + Send + Sync {
    /// A zeroed instance of the unit.
    const ZEROED: Self;

    /// Creates a unit from a multi-dimensional unit with arbitrary dimension.
    fn from_arbitrary_dimensions(dimensions: &[u64]) -> Self;

    /// Converts the unit into a scalar value, given a price.
    fn value(&self, price: &Self) -> u64;
}

/// A multi-dimensional gas unit.
pub type TupleGasUnit<const N: usize> = [u64; N];

impl<const N: usize> GasUnit for TupleGasUnit<N> {
    const ZEROED: Self = [0; N];

    fn from_arbitrary_dimensions(dimensions: &[u64]) -> Self {
        // as demonstrated on the link below, the compiler can easily optimize the conversion as if
        // it is a transparent type.
        //
        // https://rust.godbolt.org/z/rPhaxnPEY
        let mut unit = Self::ZEROED;
        unit.iter_mut()
            .zip(dimensions.iter().copied())
            .for_each(|(a, b)| *a = b);
        unit
    }

    fn value(&self, price: &Self) -> u64 {
        self.iter()
            .zip(price.iter().copied())
            .map(|(a, b)| a.saturating_mul(b))
            .fold(0, |a, b| a.saturating_add(b))
    }
}
