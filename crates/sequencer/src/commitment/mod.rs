//! Module for handling sequencer commitments
//!
//! A sequencer commitment is a data structure that groups multiple L2 blocks together
//! and publishes them as a single unit to the Data Availability (DA) layer. When a
//! commitment is published to the DA layer, all L2 blocks within it become finalized.
//! This batching mechanism helps optimize DA costs while maintaining the security
//! properties of the rollup.
//!
//! The commitment process involves:
//! - Collecting L2 blocks that are ready to be finalized
//! - Creating a commitment that includes these blocks
//! - Publishing the commitment to the DA layer
//! - Tracking the commitment's status until it's finalized
//!
//! This module contains components for managing and processing commitments:
//! - controller: Handles the control flow of commitment operations
//! - helpers: Utility functions for commitment processing
//! - service: Core commitment service implementation

/// Controls the flow of commitment operations and manages commitment state
mod controller;

/// Provides utility functions for commitment processing and validation
mod helpers;

/// Core implementation of the commitment service
pub(crate) mod service;
