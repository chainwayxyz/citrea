use anyhow::anyhow;
#[cfg(feature = "native")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Default)]
#[cfg_attr(feature = "native", derive(Serialize, Deserialize))]
pub enum SpecId {
    #[default]
    Genesis = 0,
    Fork1 = 1,
    Fork2 = 2,
}

impl TryFrom<u32> for SpecId {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => SpecId::Genesis,
            1 => SpecId::Fork1,
            2 => SpecId::Fork2,
            _ => return Err(anyhow!("No spec with this ID")),
        })
    }
}
