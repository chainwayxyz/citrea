/// A trait for state diffs used by Storage implementations, used in Zk mode.
pub trait StateDiff {
    /// Returns the diff in a format the Zk verifier can work with
    fn into_format(self) -> Vec<(Vec<u8>, Option<Vec<u8>>)>;

    /// Merge two state diffs, updating the left-hand side with the right-hand side
    fn merge(&mut self, other: Self);
}
