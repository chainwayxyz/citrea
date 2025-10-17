//! Job management for Bitcoin DA transactions.
//!
//! This module provides a persistent job queue system.
//! Jobs are stored in the database by uuidv7 and processed chronologically.
//! Supports partial sending of chunked transactions and recovery

use crate::job::error::JobServiceError;

/// Job related error types
pub mod error;
pub mod rpc;
/// Core job queue implementation and state management
pub mod service;

mod metrics;

type Result<T> = std::result::Result<T, JobServiceError>;
