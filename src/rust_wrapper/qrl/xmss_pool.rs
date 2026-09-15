use super::hashing::sha2_256;
use super::xmss_fast::XMSSFast;
use crate::rust_wrapper::errors::QRLError;
use crate::rust_wrapper::qrl::xmss_base::TSEED;
use crossbeam_channel::bounded;
use crossbeam_channel::Receiver;
use rayon;
use std::collections::VecDeque;
use zeroize::Zeroizing;
pub struct XMSSPool {
    base_seed: Zeroizing<TSEED>,
    height: u8,
    current_index: usize,
    max_cache_size: usize,
    pub thread_pool: rayon::ThreadPool,
    cache: VecDeque<Receiver<Result<XMSSFast, QRLError>>>,
}

impl XMSSPool {
    pub fn new(
        base_seed: TSEED,
        height: u8,
        starting_index: usize,
        max_cache_size: usize,
    ) -> Result<Self, rayon::ThreadPoolBuildError> {
        // Wrap the seed before the fallible pool construction. If that fails,
        // the caller-provided seed copy is still erased during unwinding.
        let base_seed = Zeroizing::new(base_seed);
        let thread_pool = rayon::ThreadPoolBuilder::new().build()?;
        let mut xmss_pool = Self {
            base_seed,
            height,
            current_index: starting_index,
            max_cache_size,
            thread_pool,
            cache: VecDeque::new(),
        };
        xmss_pool.fill_cache();
        Ok(xmss_pool)
    }

    fn prepare_tree(&self, index: usize) -> Result<XMSSFast, QRLError> {
        // FIXME: Check with Leon. The commented code is a proposal
        //    index++;
        //    while(index>0)
        //    {
        //        tmp_seed.push_back(static_cast<unsigned char &&>(index & 0xFF));
        //        index >>= 8;
        //    }
        //    auto stake_seed = shake256(48, tmp_seed);

        // This was the original approach in python
        let next_index = index
            .checked_add(1)
            .ok_or_else(|| QRLError::InvalidArgument("XMSS pool index overflow".to_owned()))?;
        let decimal_index = Zeroizing::new(next_index.to_string());
        let input_capacity = self
            .base_seed
            .len()
            .checked_mul(2)
            .and_then(|length| length.checked_add(decimal_index.len()))
            .ok_or_else(|| QRLError::InvalidArgument("XMSS pool input is too large".to_owned()))?;
        let mut seed_input = Zeroizing::new(Vec::with_capacity(input_capacity));
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in self.base_seed.iter() {
            seed_input.push(HEX[(byte >> 4) as usize]);
            seed_input.push(HEX[(byte & 0x0f) as usize]);
        }
        seed_input.extend_from_slice(decimal_index.as_bytes());

        let digest = Zeroizing::new(sha2_256(&seed_input));
        let mut stake_seed = Zeroizing::new(Vec::with_capacity(48));
        stake_seed.extend_from_slice(&digest);
        stake_seed.extend_from_slice(&digest[..16]);
        XMSSFast::new(
            std::mem::take(&mut *stake_seed),
            self.height,
            None,
            None,
            None,
        )
    }

    fn fill_cache(&mut self) {
        let Some(start) = self.current_index.checked_add(self.cache.len()) else {
            return;
        };
        let Some(end) = self.current_index.checked_add(self.max_cache_size) else {
            return;
        };
        for i in start..end {
            let (s, r) = bounded(1);
            self.cache.push_back(r);
            self.thread_pool.install(|| {
                s.send(self.prepare_tree(i)).unwrap();
            });
        }
    }

    pub fn get_next_tree(&mut self) -> Result<XMSSFast, QRLError> {
        if self.cache.is_empty() {
            let answer = self.prepare_tree(self.current_index)?;
            self.current_index = self
                .current_index
                .checked_add(1)
                .ok_or_else(|| QRLError::InvalidArgument("XMSS pool index overflow".to_owned()))?;
            self.fill_cache();
            return Ok(answer);
        }
        let r_result = self.cache.front().unwrap().recv();
        self.current_index = self
            .current_index
            .checked_add(1)
            .ok_or_else(|| QRLError::InvalidArgument("XMSS pool index overflow".to_owned()))?;
        let next_tree = match r_result {
            Ok(r) => {
                self.cache.pop_front();
                r?
            }
            Err(_) => self.prepare_tree(self.current_index)?,
        };
        self.fill_cache();
        Ok(next_tree)
    }

    pub fn is_available(&self) -> bool {
        match self.cache.front() {
            Some(r) => r.is_full(),
            None => false,
        }
    }

    pub fn get_current_index(&self) -> usize {
        self.current_index
    }
}
