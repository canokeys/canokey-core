// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
pub mod codec;
pub mod domain;
#[cfg(feature = "pass")]
pub(crate) mod output;
pub mod service;
