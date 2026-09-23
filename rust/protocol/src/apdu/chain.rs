// SPDX-License-Identifier: Apache-2.0
use super::{CommandInfo, Error, Header};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainStep {
    /// Discard the previous command's provisional semantic state before use.
    pub restarted: bool,
    pub last: bool,
    pub total: u32,
}

/// Metadata only: the caller owns one incremental consumer, never a chain-sized
/// buffer. Apply after frame validation; overflow/reset aborts that consumer.
#[derive(Default)]
pub struct CommandChain {
    header: Option<Header>,
    total: u32,
}

impl CommandChain {
    pub const fn new() -> Self {
        Self {
            header: None,
            total: 0,
        }
    }
    pub fn active(&self) -> bool {
        self.header.is_some()
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn accept(&mut self, info: CommandInfo, limit: u32) -> Result<ChainStep, Error> {
        let header = info.header.unchained();
        let restarted = self.header != Some(header);
        let total = if restarted { 0 } else { self.total };
        let Some(total) = total
            .checked_add(u32::from(info.lc))
            .filter(|n| *n <= limit)
        else {
            self.reset();
            return Err(Error::Length);
        };
        let last = !info.header.chained();
        if last {
            self.reset();
        } else {
            self.header = Some(header);
            self.total = total;
        }
        Ok(ChainStep {
            restarted,
            last,
            total,
        })
    }
}
