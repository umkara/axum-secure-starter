//! A layered HTTP API server.
//!
//! ```text
//! api/        HTTP edge      — routing, DTOs, extractors, middleware
//! service/    business rules — policy, transactions, orchestration
//! repository/ persistence    — trait per aggregate, SQLite implementations
//! domain/     entities       — data and its own invariants
//! security/   cross-cutting  — hashing, tokens, authn/authz, headers
//! ```
//!
//! Dependencies point inward only: `api` knows `service`, `service` knows
//! `repository` traits, and nothing below `api` knows about HTTP.
//!
//! Exposed as a library so integration tests can build and drive the exact
//! router the binary serves, rather than a lookalike.

pub mod api;
pub mod config;
pub mod db;
pub mod domain;
pub mod error;
pub mod net;
pub mod repository;
pub mod security;
pub mod server;
pub mod service;
pub mod state;
pub mod telemetry;
