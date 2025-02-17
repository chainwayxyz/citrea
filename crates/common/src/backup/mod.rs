//! Database backup and restoration functionality for Citrea nodes.
//!
//! This module provides functionality to create consistent backups of Citrea nodes'
//! databases while ensuring data integrity and atomicity. It handles both required
//! databases (ledger, state, native-db) and the optional MMR database used by the
//! light client prover. The module exposes `start_l1_processing` and `start_l2_processing`
//! methods to ensure no blocks are being processed during backup creation.
//!
//! # Architecture
//!
//! The backup system consists of two main components:
//!
//! - [`BackupManager`]: Coordinates backup/validation/restore operations and manages processing locks
//! - RPC: Exposes backup creation/validation functionality via JSON-RPC endpoints
//!
//! # Features
//!
//! - Atomic backup and restore operations
//! - Coordination with L1/L2 block processing via locks
//! - Backup validation and integrity checking
//! - Safe restoration with automatic backup of existing data
//! - RPC endpoints for backup creation and validation
//!
//! # Safety
//!
//! The backup system ensures consistency by:
//! - Acquiring L1/L2 processing locks during backup to prevent concurrent modifications
//! - Validating backup integrity before any restoration attempt
//! - Using atomic filesystem operations for restoration
//! - Automatically backing up existing databases with .bak extension during restore
//!
//! # Directory Structure
//!
//! A backup directory contains the following structure:
//! ```text
//! ├── .metadata     # Holds node kind and backup_id->l2_height mapping
//! ├── ledger/       # Required - stores ledger database
//! ├── state/        # Required - stores state database
//! ├── native-db/    # Required - stores native database
//! └── mmr/          # Optional - used by light client prover
//! ```
mod manager;
mod rpc;
mod utils;

pub use manager::*;
pub use rpc::*;
