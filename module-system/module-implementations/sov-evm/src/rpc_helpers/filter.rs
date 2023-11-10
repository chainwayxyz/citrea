use std::collections::HashSet;
use std::hash::Hash;

use itertools::{EitherOrBoth::*, Itertools};
use reth_primitives::{Address, BlockHash, H256};
use revm::primitives::B256;
use serde::{
    de::{DeserializeOwned, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};

#[derive(Default, Debug, PartialEq, Eq, Clone, serde::Deserialize, serde::Serialize)]
/// FilterSet is a set of values that will be used to filter logs
pub struct FilterSet<T: Eq + Hash>(pub HashSet<T>);

/// A single topic
/// Which is a set of topics
pub type Topic = FilterSet<H256>;

/// A block Number (or tag - "latest", "earliest", "pending")
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum BlockNumberOrTag {
    /// Latest block
    #[default]
    Latest,
    /// Finalized block accepted as canonical
    Finalized,
    /// Safe head block
    Safe,
    /// Earliest block (genesis)
    Earliest,
    /// Pending block (not yet part of the blockchain)
    Pending,
    /// Block by number from canon chain
    Number(u64),
}

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

/// filter for eth_getLogs
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    /// Filter block options, specifying on which blocks the filter should
    /// match.
    // https://eips.ethereum.org/EIPS/eip-234
    pub block_option: FilterBlockOption,
    /// Filter for the address of the log, can be
    pub address: FilterSet<reth_primitives::Address>,
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

impl<T: Clone + Eq + Hash> FilterSet<T> {
    /// Returns a ValueOrArray inside an Option, so that:
    ///   - If the filter is empty, it returns None
    ///   - If the filter has only 1 value, it returns the single value
    ///   - Otherwise it returns an array of values
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
        for topic_tuple in topics.iter().zip_longest(log.topics.iter()) {
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

    /// TODO: Implement after deciding on what to do with archival nodes
    pub fn filter_block_range(&self) -> bool {
        true
    }

    /// Checks if the given filter block hash matches the block hash of the log
    pub fn filter_block_hash(&self, block_hash: &B256) -> bool {
        match self.block_option {
            FilterBlockOption::AtBlockHash(hash) => {
                if &hash == block_hash {
                    return true;
                }
                return false;
            }
            FilterBlockOption::Range { .. } => {
                /*filter block range*/
                return true;
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

/// Returns true if the log matches the filter and should be included
pub fn log_matches_filter(
    log: &reth_primitives::Log,
    filter: &Filter,
    topics: &[FilterSet<B256>; 4],
    block_hash: &BlockHash,
) -> bool {
    if !filter.filter_block_range()
        || !filter.filter_block_hash(block_hash)
        || !filter.filter_topics(&log, topics)
        || !filter.filter_address(&log, &filter.address)
    {
        return false;
    }
    true
}
