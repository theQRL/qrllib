use super::xmss_fast::XMSSFast;
use crate::rust_wrapper::errors::QRLError;
use crate::rust_wrapper::qrl::xmss_base::TSEED;
use crate::rust_wrapper::shasha::shasha::sha2_256;
use crossbeam_channel::bounded;
use crossbeam_channel::Receiver;
use rayon;
use std::collections::VecDeque;
pub struct XMSSPool {
    base_seed: TSEED,
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
        let seed_str = hex::encode(&self.base_seed) + &(index + 1).to_string();
        let mut stake_seed = sha2_256(&seed_str.as_bytes().to_vec());
        stake_seed.extend_from_within(0..16);
        Ok(XMSSFast::new(stake_seed, self.height, None, None, None)?)
    }

    fn fill_cache(&mut self) {
        let start = self.current_index + self.cache.len();
        let end = self.current_index + self.max_cache_size;
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
            let answer = self.prepare_tree(self.current_index);
            self.current_index += 1;
            self.fill_cache();
            return answer;
        }
        let r_result = self.cache.front().unwrap().recv();
        self.current_index += 1;
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
