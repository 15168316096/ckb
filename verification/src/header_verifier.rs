use super::Verifier;
use crate::{
    BlockErrorKind, EpochError, NumberError, PowError, TimestampError, UnknownParentError,
    ALLOWED_FUTURE_BLOCKTIME,
};
use ckb_error::Error;
use ckb_pow::PowEngine;
use ckb_traits::BlockMedianTimeContext;
use ckb_types::prelude::*;
use ckb_types::{
    constants::HEADER_VERSION,
    core::{EpochExt, HeaderView},
};
use faketime::unix_time_as_millis;
use std::marker::PhantomData;
use std::sync::Arc;

pub trait HeaderResolver {
    fn header(&self) -> &HeaderView;
    /// resolves parent header
    fn parent(&self) -> Option<&HeaderView>;
    /// resolves header difficulty
    fn epoch(&self) -> Option<&EpochExt>;
}

pub struct HeaderVerifier<'a, T, M> {
    pub pow: Arc<dyn PowEngine>,
    block_median_time_context: &'a M,
    _phantom: PhantomData<T>,
}

impl<'a, T, M: BlockMedianTimeContext> HeaderVerifier<'a, T, M> {
    pub fn new(block_median_time_context: &'a M, pow: Arc<dyn PowEngine>) -> Self {
        HeaderVerifier {
            pow,
            block_median_time_context,
            _phantom: PhantomData,
        }
    }
}

impl<'a, T: HeaderResolver, M: BlockMedianTimeContext> Verifier for HeaderVerifier<'a, T, M> {
    type Target = T;
    fn verify(&self, target: &T) -> Result<(), Error> {
        let header = target.header();
        VersionVerifier::new(header).verify()?;
        // POW check first
        PowVerifier::new(header, &self.pow).verify()?;
        let parent = target.parent().ok_or_else(|| UnknownParentError {
            parent_hash: header.parent_hash().to_owned(),
        })?;
        NumberVerifier::new(parent, header).verify()?;
        TimestampVerifier::new(self.block_median_time_context, header).verify()?;
        EpochVerifier::verify(target)?;
        Ok(())
    }
}

pub struct VersionVerifier<'a> {
    header: &'a HeaderView,
}

impl<'a> VersionVerifier<'a> {
    pub fn new(header: &'a HeaderView) -> Self {
        VersionVerifier { header }
    }

    pub fn verify(&self) -> Result<(), Error> {
        if self.header.version() != HEADER_VERSION {
            return Err(BlockErrorKind::Version.into());
        }
        Ok(())
    }
}

pub struct TimestampVerifier<'a, M> {
    header: &'a HeaderView,
    block_median_time_context: &'a M,
    now: u64,
}

impl<'a, M: BlockMedianTimeContext> TimestampVerifier<'a, M> {
    pub fn new(block_median_time_context: &'a M, header: &'a HeaderView) -> Self {
        TimestampVerifier {
            block_median_time_context,
            header,
            now: unix_time_as_millis(),
        }
    }

    pub fn verify(&self) -> Result<(), Error> {
        // skip genesis block
        if self.header.is_genesis() {
            return Ok(());
        }

        let min = self
            .block_median_time_context
            .block_median_time(&self.header.data().raw().parent_hash());
        if self.header.timestamp() <= min {
            return Err(TimestampError::BlockTimeTooOld {
                min,
                actual: self.header.timestamp(),
            }
            .into());
        }
        let max = self.now + ALLOWED_FUTURE_BLOCKTIME;
        if self.header.timestamp() > max {
            return Err(TimestampError::BlockTimeTooNew {
                max,
                actual: self.header.timestamp(),
            }
            .into());
        }
        Ok(())
    }
}

pub struct NumberVerifier<'a> {
    parent: &'a HeaderView,
    header: &'a HeaderView,
}

impl<'a> NumberVerifier<'a> {
    pub fn new(parent: &'a HeaderView, header: &'a HeaderView) -> Self {
        NumberVerifier { parent, header }
    }

    pub fn verify(&self) -> Result<(), Error> {
        if self.header.number() != self.parent.number() + 1 {
            return Err(NumberError {
                expected: self.parent.number() + 1,
                actual: self.header.number(),
            }
            .into());
        }
        Ok(())
    }
}

pub struct EpochVerifier<T> {
    phantom: PhantomData<T>,
}

impl<T: HeaderResolver> EpochVerifier<T> {
    pub fn verify(target: &T) -> Result<(), Error> {
        let epoch = target.epoch().ok_or_else(|| EpochError::AncestorNotFound)?;
        let header = target.header();
        let actual_epoch_with_fraction = header.epoch();
        let block_number = header.number();
        let epoch_with_fraction = epoch.number_with_fraction(block_number);
        if actual_epoch_with_fraction != epoch_with_fraction {
            return Err(EpochError::NumberMismatch {
                expected: epoch_with_fraction.full_value(),
                actual: actual_epoch_with_fraction.full_value(),
            }
            .into());
        }
        let actual_difficulty = target.header().difficulty();
        if epoch.difficulty() != &actual_difficulty {
            return Err(EpochError::DifficultyMismatch {
                expected: epoch.difficulty().pack(),
                actual: actual_difficulty.pack(),
            }
            .into());
        }
        Ok(())
    }
}

pub struct PowVerifier<'a> {
    header: &'a HeaderView,
    pow: Arc<dyn PowEngine>,
}

impl<'a> PowVerifier<'a> {
    pub fn new(header: &'a HeaderView, pow: &Arc<dyn PowEngine>) -> Self {
        PowVerifier {
            header,
            pow: Arc::clone(pow),
        }
    }

    pub fn verify(&self) -> Result<(), Error> {
        if self.pow.verify(&self.header.data()) {
            Ok(())
        } else {
            Err(PowError::InvalidNonce.into())
        }
    }
}
