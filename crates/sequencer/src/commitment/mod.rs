//! Module for handling commitment-related functionality in the sequencer
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
