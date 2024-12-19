// https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc-types/src/eth/filter.rs
use std::collections::HashSet;
use std::hash::Hash;
use std::iter::StepBy;
use std::ops::{Range, RangeFrom, RangeInclusive, RangeTo};

use alloy_primitives::{Address, BlockHash, Bloom, BloomInput, B256, U64};
use itertools::EitherOrBoth::*;
use itertools::Itertools;
use reth_primitives::BlockNumberOrTag;
use reth_rpc_eth_types::error::EthApiError;
use reth_rpc_server_types::result::rpc_error_with_code;
use serde::de::{DeserializeOwned, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The maximum number of blocks that can be queried in a single eth_getLogs request.
pub const DEFAULT_MAX_BLOCKS_PER_FILTER: u64 = 1_000;
/// The maximum number of logs that can be returned in a single eth_getLogs response.
pub const DEFAULT_MAX_LOGS_PER_RESPONSE: usize = 5_000;
/// The maximum number of headers we read at once when handling a range filter.
pub const MAX_HEADERS_RANGE: u64 = 1_000; // with ~530bytes? per header this is ~500kb?

/// Helper type to represent a bloom filter used for matching logs.
#[derive(Default, Debug)]
pub struct BloomFilter(Vec<Bloom>);

impl From<Vec<Bloom>> for BloomFilter {
    fn from(src: Vec<Bloom>) -> Self {
        BloomFilter(src)
    }
}

impl BloomFilter {
    /// Returns whether the given bloom matches the list of Blooms in the current filter.
    /// If the filter is empty (the list is empty), then any bloom matches
    /// Otherwise, there must be at least one matchee for the BloomFilter to match.
    pub fn matches(&self, bloom: Bloom) -> bool {
        self.0.is_empty() || self.0.iter().any(|a| bloom.contains(a))
    }
}

#[derive(Default, Debug, PartialEq, Eq, Clone, serde::Deserialize, serde::Serialize)]
/// FilterSet is a set of values that will be used to filter logs
pub struct FilterSet<T: Eq + Hash>(pub HashSet<T>);

/// A single topic
/// Which is a set of topics
pub type Topic = FilterSet<B256>;

/// Represents the target range of blocks for the filter
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum FilterBlockOption {
    /// Represents a range of blocks with optional from and to blocks
    ///
    /// Note: ranges are considered to be __inclusive__
    Range {
        /// The block number or tag this filter should start at.
        from_block: Option<BlockNumberOrTag>,
        /// The block number or that this filter should end at.
        to_block: Option<BlockNumberOrTag>,
    },
    /// The hash of the block if the filter only targets a single block
    AtBlockHash(B256),
}

impl Default for FilterBlockOption {
    fn default() -> Self {
        FilterBlockOption::Range {
            from_block: None,
            to_block: None,
        }
    }
}

impl FilterBlockOption {
    /// Returns the `toBlock` value, if any
    pub fn get_to_block(&self) -> Option<&BlockNumberOrTag> {
        match self {
            FilterBlockOption::Range { to_block, .. } => to_block.as_ref(),
            FilterBlockOption::AtBlockHash(_) => None,
        }
    }

    /// Returns the `fromBlock` value, if any
    pub fn get_from_block(&self) -> Option<&BlockNumberOrTag> {
        match self {
            FilterBlockOption::Range { from_block, .. } => from_block.as_ref(),
            FilterBlockOption::AtBlockHash(_) => None,
        }
    }

    /// Returns the range (`fromBlock`, `toBlock`) if this is a range filter.
    pub fn as_range(&self) -> (Option<&BlockNumberOrTag>, Option<&BlockNumberOrTag>) {
        match self {
            FilterBlockOption::Range {
                from_block,
                to_block,
            } => (from_block.as_ref(), to_block.as_ref()),
            FilterBlockOption::AtBlockHash(_) => (None, None),
        }
    }
}

impl From<BlockNumberOrTag> for FilterBlockOption {
    fn from(block: BlockNumberOrTag) -> Self {
        let block = Some(block);
        FilterBlockOption::Range {
            from_block: block,
            to_block: block,
        }
    }
}

impl From<U64> for FilterBlockOption {
    fn from(block: U64) -> Self {
        BlockNumberOrTag::from(block).into()
    }
}

impl From<u64> for FilterBlockOption {
    fn from(block: u64) -> Self {
        BlockNumberOrTag::from(block).into()
    }
}

impl<T: Into<BlockNumberOrTag>> From<Range<T>> for FilterBlockOption {
    fn from(r: Range<T>) -> Self {
        let from_block = Some(r.start.into());
        let to_block = Some(r.end.into());
        FilterBlockOption::Range {
            from_block,
            to_block,
        }
    }
}

impl<T: Into<BlockNumberOrTag>> From<RangeTo<T>> for FilterBlockOption {
    fn from(r: RangeTo<T>) -> Self {
        let to_block = Some(r.end.into());
        FilterBlockOption::Range {
            from_block: Some(BlockNumberOrTag::Earliest),
            to_block,
        }
    }
}

impl<T: Into<BlockNumberOrTag>> From<RangeFrom<T>> for FilterBlockOption {
    fn from(r: RangeFrom<T>) -> Self {
        let from_block = Some(r.start.into());
        FilterBlockOption::Range {
            from_block,
            to_block: Some(BlockNumberOrTag::Latest),
        }
    }
}

impl From<B256> for FilterBlockOption {
    fn from(hash: B256) -> Self {
        FilterBlockOption::AtBlockHash(hash)
    }
}

impl FilterBlockOption {
    /// Sets the block number this range filter should start at.
    #[must_use]
    pub fn set_from_block(&self, block: BlockNumberOrTag) -> Self {
        let to_block = if let FilterBlockOption::Range { to_block, .. } = self {
            *to_block
        } else {
            None
        };

        FilterBlockOption::Range {
            from_block: Some(block),
            to_block,
        }
    }

    /// Sets the block number this range filter should end at.
    #[must_use]
    pub fn set_to_block(&self, block: BlockNumberOrTag) -> Self {
        let from_block = if let FilterBlockOption::Range { from_block, .. } = self {
            *from_block
        } else {
            None
        };

        FilterBlockOption::Range {
            from_block,
            to_block: Some(block),
        }
    }

    /// Pins the block hash this filter should target.
    #[must_use]
    pub fn set_hash(&self, hash: B256) -> Self {
        FilterBlockOption::AtBlockHash(hash)
    }
}

// https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc-types/src/eth/filter.rs#L249
/// filter for eth_getLogs
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    /// Filter block options, specifying on which blocks the filter should
    /// match.
    // https://eips.ethereum.org/EIPS/eip-234
    pub block_option: FilterBlockOption,
    /// Filter for the address of the log, can be
    pub address: FilterSet<alloy_primitives::Address>,
    /// Filter for the topics of the log
    pub topics: [Topic; 4],
}

impl<T: Eq + Hash> From<T> for FilterSet<T> {
    fn from(src: T) -> Self {
        FilterSet(HashSet::from([src]))
    }
}

impl<T: Eq + Hash> From<Vec<T>> for FilterSet<T> {
    fn from(src: Vec<T>) -> Self {
        FilterSet(HashSet::from_iter(src.into_iter().map(Into::into)))
    }
}

impl<T: Eq + Hash> From<ValueOrArray<T>> for FilterSet<T> {
    fn from(src: ValueOrArray<T>) -> Self {
        match src {
            ValueOrArray::Value(val) => val.into(),
            ValueOrArray::Array(arr) => arr.into(),
        }
    }
}

impl<T: Eq + Hash> From<ValueOrArray<Option<T>>> for FilterSet<T> {
    fn from(src: ValueOrArray<Option<T>>) -> Self {
        match src {
            ValueOrArray::Value(None) => FilterSet(HashSet::new()),
            ValueOrArray::Value(Some(val)) => val.into(),
            ValueOrArray::Array(arr) => {
                // If the array contains at least one `null` (ie. None), as it's considered
                // a "wildcard" value, the whole filter should be treated as matching everything,
                // thus is empty.
                if arr.iter().contains(&None) {
                    FilterSet(HashSet::new())
                } else {
                    // Otherwise, we flatten the array, knowing there are no `None` values
                    arr.into_iter().flatten().collect::<Vec<T>>().into()
                }
            }
        }
    }
}

impl<T: Eq + Hash> FilterSet<T> {
    /// Returns wheter the filter is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns whether the given value matches the filter. It the filter is empty
    /// any value matches. Otherwise, the filter must include the value
    pub fn matches(&self, value: &T) -> bool {
        self.is_empty() || self.0.contains(value)
    }
}

impl<T: AsRef<[u8]> + Eq + Hash> FilterSet<T> {
    /// Returns a list of Bloom (BloomFilter) corresponding to the filter's values
    pub fn to_bloom_filter(&self) -> BloomFilter {
        self.0
            .iter()
            .map(|a| BloomInput::Raw(a.as_ref()).into())
            .collect::<Vec<Bloom>>()
            .into()
    }
}

impl<T: Clone + Eq + Hash> FilterSet<T> {
    /// Returns a ValueOrArray inside an Option, so that:
    ///   - If the filter is empty, it returns None
    ///   - If the filter has only 1 value, it returns the single value
    ///   - Otherwise it returns an array of values
    ///
    /// This should be useful for serialization
    pub fn to_value_or_array(&self) -> Option<ValueOrArray<T>> {
        let mut values = self.0.iter().cloned().collect::<Vec<T>>();
        match values.len() {
            0 => None,
            1 => Some(ValueOrArray::Value(
                values.pop().expect("values length is one"),
            )),
            _ => Some(ValueOrArray::Array(values)),
        }
    }
}

impl Filter {
    /// Creates a new, empty filter
    pub fn new() -> Self {
        Self::default()
    }
    /// Returns the numeric value of the `fromBlock` field
    pub fn get_block_hash(&self) -> Option<B256> {
        match self.block_option {
            FilterBlockOption::AtBlockHash(hash) => Some(hash),
            FilterBlockOption::Range { .. } => None,
        }
    }

    /// Filters the topics of the log against the filter topics
    pub fn filter_topics(&self, log: &reth_primitives::Log, topics: &[Topic]) -> bool {
        for topic_tuple in topics.iter().zip_longest(log.topics().iter()) {
            match topic_tuple {
                // We exhausted the `log.topics`, so if there's a filter set for
                // this topic index, there is no match. Otherwise (empty filter), continue.
                Left(filter_topic) => {
                    if !filter_topic.is_empty() {
                        return false;
                    }
                }
                // We exhausted the filter topics, therefore any subsequent log topic
                // will match.
                Right(_) => {
                    return true;
                }
                // Check that `log_topic` is included in `filter_topic`
                Both(filter_topic, log_topic) => {
                    if !filter_topic.matches(log_topic) {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Checks if addresses match the filter
    pub fn filter_address(&self, log: &reth_primitives::Log, address: &FilterSet<Address>) -> bool {
        if address.0.is_empty() || address.0.contains(&log.address) {
            return true;
        }
        false
    }

    /// TODO: Update after deciding on what to do with archival nodes
    pub fn filter_block_range(&self, block_number: &u64) -> bool {
        let mut res = true;

        if let Some(BlockNumberOrTag::Number(num)) = self.block_option.get_from_block() {
            if num > block_number {
                res = false;
            }
        }

        if let Some(to) = self.block_option.get_to_block() {
            match to {
                BlockNumberOrTag::Number(num) => {
                    if num < block_number {
                        res = false;
                    }
                }
                BlockNumberOrTag::Earliest => {
                    res = false;
                }
                _ => {}
            }
        }
        res
    }

    /// Checks if the given filter block hash matches the block hash of the log
    pub fn filter_block_hash(&self, block_hash: &B256) -> bool {
        match self.block_option {
            FilterBlockOption::AtBlockHash(hash) => {
                if &hash == block_hash {
                    return true;
                }
                false
            }
            FilterBlockOption::Range { .. } => {
                /*filter block range*/
                true
            }
        }
    }
}

impl Serialize for Filter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("Filter", 5)?;
        match self.block_option {
            FilterBlockOption::Range {
                from_block,
                to_block,
            } => {
                if let Some(ref from_block) = from_block {
                    s.serialize_field("fromBlock", from_block)?;
                }

                if let Some(ref to_block) = to_block {
                    s.serialize_field("toBlock", to_block)?;
                }
            }

            FilterBlockOption::AtBlockHash(ref h) => s.serialize_field("blockHash", h)?,
        }

        if let Some(address) = self.address.to_value_or_array() {
            s.serialize_field("address", &address)?;
        }

        let mut filtered_topics = Vec::new();
        let mut filtered_topics_len = 0;
        for (i, topic) in self.topics.iter().enumerate() {
            if !topic.is_empty() {
                filtered_topics_len = i + 1;
            }
            filtered_topics.push(topic.to_value_or_array());
        }
        filtered_topics.truncate(filtered_topics_len);
        s.serialize_field("topics", &filtered_topics)?;

        s.end()
    }
}

type RawAddressFilter = ValueOrArray<Option<Address>>;
type RawTopicsFilter = Vec<Option<ValueOrArray<Option<B256>>>>;

impl<'de> Deserialize<'de> for Filter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FilterVisitor;

        impl<'de> Visitor<'de> for FilterVisitor {
            type Value = Filter;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("Filter object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut from_block: Option<Option<BlockNumberOrTag>> = None;
                let mut to_block: Option<Option<BlockNumberOrTag>> = None;
                let mut block_hash: Option<Option<B256>> = None;
                let mut address: Option<Option<RawAddressFilter>> = None;
                let mut topics: Option<Option<RawTopicsFilter>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "fromBlock" => {
                            if from_block.is_some() {
                                return Err(serde::de::Error::duplicate_field("fromBlock"));
                            }
                            if block_hash.is_some() {
                                return Err(serde::de::Error::custom(
                                    "fromBlock not allowed with blockHash",
                                ));
                            }
                            from_block = Some(map.next_value()?)
                        }
                        "toBlock" => {
                            if to_block.is_some() {
                                return Err(serde::de::Error::duplicate_field("toBlock"));
                            }
                            if block_hash.is_some() {
                                return Err(serde::de::Error::custom(
                                    "toBlock not allowed with blockHash",
                                ));
                            }
                            to_block = Some(map.next_value()?)
                        }
                        "blockHash" => {
                            if block_hash.is_some() {
                                return Err(serde::de::Error::duplicate_field("blockHash"));
                            }
                            if from_block.is_some() || to_block.is_some() {
                                return Err(serde::de::Error::custom(
                                    "fromBlock,toBlock not allowed with blockHash",
                                ));
                            }
                            block_hash = Some(map.next_value()?)
                        }
                        "address" => {
                            if address.is_some() {
                                return Err(serde::de::Error::duplicate_field("address"));
                            }
                            address = Some(map.next_value()?)
                        }
                        "topics" => {
                            if topics.is_some() {
                                return Err(serde::de::Error::duplicate_field("topics"));
                            }
                            topics = Some(map.next_value()?)
                        }

                        key => {
                            return Err(serde::de::Error::unknown_field(
                                key,
                                &["fromBlock", "toBlock", "address", "topics", "blockHash"],
                            ))
                        }
                    }
                }

                let from_block = from_block.unwrap_or_default();
                let to_block = to_block.unwrap_or_default();
                let block_hash = block_hash.unwrap_or_default();
                let address = address.flatten().map(|a| a.into()).unwrap_or_default();
                let topics_vec = topics.flatten().unwrap_or_default();

                // maximum allowed filter len
                if topics_vec.len() > 4 {
                    return Err(serde::de::Error::custom("exceeded maximum topics len"));
                }
                let mut topics: [Topic; 4] = [
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    Default::default(),
                ];
                for (idx, topic) in topics_vec.into_iter().enumerate() {
                    topics[idx] = topic.map(|t| t.into()).unwrap_or_default();
                }

                let block_option = if let Some(block_hash) = block_hash {
                    FilterBlockOption::AtBlockHash(block_hash)
                } else {
                    FilterBlockOption::Range {
                        from_block,
                        to_block,
                    }
                };

                Ok(Filter {
                    block_option,
                    address,
                    topics,
                })
            }
        }

        deserializer.deserialize_any(FilterVisitor)
    }
}

/// Union type for representing a single value or a vector of values inside a filter
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum ValueOrArray<T> {
    /// A single value
    Value(T),
    /// A vector of values
    Array(Vec<T>),
}

impl From<Address> for ValueOrArray<Address> {
    fn from(src: Address) -> Self {
        ValueOrArray::Value(src)
    }
}

impl From<Vec<Address>> for ValueOrArray<Address> {
    fn from(src: Vec<Address>) -> Self {
        ValueOrArray::Array(src)
    }
}

impl From<Vec<B256>> for ValueOrArray<B256> {
    fn from(src: Vec<B256>) -> Self {
        ValueOrArray::Array(src)
    }
}

impl<T> Serialize for ValueOrArray<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ValueOrArray::Value(inner) => inner.serialize(serializer),
            ValueOrArray::Array(inner) => inner.serialize(serializer),
        }
    }
}

impl<'a, T> Deserialize<'a> for ValueOrArray<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<ValueOrArray<T>, D::Error>
    where
        D: Deserializer<'a>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;

        if value.is_null() {
            return Ok(ValueOrArray::Array(Vec::new()));
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Variadic<T> {
            Value(T),
            Array(Vec<T>),
        }

        match serde_json::from_value::<Variadic<T>>(value).map_err(|err| {
            serde::de::Error::custom(format!("Invalid variadic value or array type: {err}"))
        })? {
            Variadic::Value(val) => Ok(ValueOrArray::Value(val)),
            Variadic::Array(arr) => Ok(ValueOrArray::Array(arr)),
        }
    }
}

// https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc/src/eth/logs_utils.rs#L56
/// Returns true if the log matches the filter and should be included
pub fn log_matches_filter(
    log: &reth_primitives::Log,
    filter: &Filter,
    block_hash: &BlockHash,
    block_number: &u64,
) -> bool {
    if !filter.filter_block_range(block_number)
        || !filter.filter_block_hash(block_hash)
        || !filter.filter_topics(log, &filter.topics)
        || !filter.filter_address(log, &filter.address)
    {
        return false;
    }
    true
}

/// TODO: docs + discuss finalized, safe and pending
pub fn convert_block_number(
    num: BlockNumberOrTag,
    start_block: u64,
) -> Result<Option<u64>, FilterError> {
    let num = match num {
        BlockNumberOrTag::Latest => start_block,
        BlockNumberOrTag::Earliest => 0,
        // Is this okay? start_block + 1 = Latest blocks number + 1
        BlockNumberOrTag::Pending => start_block + 1,
        BlockNumberOrTag::Number(num) => num,
        // TODO: Is there a better way to handle this instead of giving the latest block?
        BlockNumberOrTag::Finalized => start_block,
        // TODO: Is there a better way to handle this instead of giving the latest block?
        BlockNumberOrTag::Safe => start_block,
    };
    Ok(Some(num))
}

/// An iterator that yields _inclusive_ block ranges of a given step size
#[derive(Debug)]
pub struct BlockRangeInclusiveIter {
    iter: StepBy<RangeInclusive<u64>>,
    step: u64,
    end: u64,
}

impl BlockRangeInclusiveIter {
    /// TODO: docs
    pub fn new(range: RangeInclusive<u64>, step: u64) -> Self {
        Self {
            end: *range.end(),
            iter: range.step_by(step as usize + 1),
            step,
        }
    }
}

impl Iterator for BlockRangeInclusiveIter {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.iter.next()?;
        let end = (start + self.step).min(self.end);
        if start > end {
            return None;
        }
        Some((start, end))
    }
}

/// Returns `true` if the bloom matches the topics
pub fn matches_topics(bloom: Bloom, topic_filters: &[BloomFilter]) -> bool {
    if topic_filters.is_empty() {
        return true;
    }

    // for each filter, iterate through the list of filter blooms. for each set of filter
    // (each BloomFilter), the given `bloom` must match at least one of them, unless the list is
    // empty (no filters).
    for filter in topic_filters.iter() {
        if !filter.matches(bloom) {
            return false;
        }
    }
    true
}

/// Returns `true` if the bloom contains one of the address blooms, or the address blooms
/// list is empty (thus, no filters)
pub fn matches_address(bloom: Bloom, address_filter: &BloomFilter) -> bool {
    address_filter.matches(bloom)
}

/// Errors that can occur in the handler implementation
#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    // #[error("filter not found")]
    // FilterNotFound(FilterId),
    /// There is a maximum number of blocks that can be queried in a single eth_getLogs request.
    #[error("query exceeds max block range {0}")]
    QueryExceedsMaxBlocks(u64),
    /// There is a maximum number of logs that can be returned in a single eth_getLogs response.
    #[error("query exceeds max results {0}")]
    QueryExceedsMaxResults(usize),
    /// Error thrown when the eth api returns an error
    #[error(transparent)]
    EthAPIError(#[from] EthApiError),
    /// Error thrown when a spawned task failed to deliver a response.
    #[error("internal filter error")]
    InternalError,
}

// convert the error
impl From<FilterError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: FilterError) -> Self {
        match err {
            // FilterError::FilterNotFound(_) => rpc_error_with_code(
            //     jsonrpsee::types::error::INVALID_PARAMS_CODE,
            //     "filter not found",
            // ),
            err @ FilterError::InternalError => rpc_error_with_code(
                jsonrpsee::types::error::INTERNAL_ERROR_CODE,
                err.to_string(),
            ),
            FilterError::EthAPIError(err) => err.into(),
            err @ FilterError::QueryExceedsMaxBlocks(_) => rpc_error_with_code(
                jsonrpsee::types::error::INVALID_PARAMS_CODE,
                err.to_string(),
            ),
            err @ FilterError::QueryExceedsMaxResults(_) => rpc_error_with_code(
                jsonrpsee::types::error::INVALID_PARAMS_CODE,
                err.to_string(),
            ),
        }
    }
}
