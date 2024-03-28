use std::fs;

use crate::{clap, CliWallet};

pub trait CliFrontEnd<RT>
where
    RT: CliWallet,
{
    type CliIntermediateRepr<U>;
}

pub trait CliTxImportArg {
    /// The chain ID of the transaction.
    fn chain_id(&self) -> u64;
}

/// An argument to the cli containing a json string
#[derive(clap::Args, PartialEq, core::fmt::Debug, Clone, PartialOrd, Ord, Eq, Hash)]
pub struct JsonStringArg {
    /// The json formatted transaction data
    #[arg(long, help = "The JSON formatted transaction")]
    pub json: String,

    /// The chain ID of the transaction.
    #[arg(long, help = "The chain ID of the transaction.")]
    pub chain_id: u64,
}

/// An argument to the cli containing a path to a file
#[derive(clap::Args, PartialEq, core::fmt::Debug, Clone, PartialOrd, Ord, Eq, Hash)]
pub struct FileNameArg {
    /// The json formatted transaction data
    #[arg(long, help = "The JSON formatted transaction")]
    pub path: String,

    /// The chain ID of the transaction.
    #[arg(long, help = "The chain ID of the transaction.")]
    pub chain_id: u64,
}

impl CliTxImportArg for JsonStringArg {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

impl CliTxImportArg for FileNameArg {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

impl TryFrom<FileNameArg> for JsonStringArg {
    type Error = std::io::Error;
    fn try_from(arg: FileNameArg) -> Result<Self, Self::Error> {
        let FileNameArg { path, chain_id } = arg;

        Ok(JsonStringArg {
            json: fs::read_to_string(path)?,
            chain_id,
        })
    }
}
