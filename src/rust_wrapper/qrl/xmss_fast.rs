use super::xmss_base::{Sign, XMSSBase, XMSSBaseTrait, TKEY, TMESSAGE, TSEED, TSIGNATURE};
use crate::rust_wrapper::errors::QRLError;
use crate::rust_wrapper::qrl::qrl_address_format::AddrFormatType;
use crate::rust_wrapper::qrl::xmss_validation::{signature_count, BDS_K, N};
use crate::rust_wrapper::xmss_alt::algsxmss_fast::{
    xmss_fast_gen_keypair, xmss_fast_sign_msg, xmss_fast_update, BDSState, TreeHashInst,
};
use crate::rust_wrapper::xmss_alt::hash_functions::HashFunction;
use crate::rust_wrapper::xmss_alt::xmss_common::XMSSParams;
use zeroize::Zeroizing;

pub struct XMSSFast {
    base: XMSSBase,
    params: XMSSParams,
    state: BDSState,
}

impl XMSSFast {
    fn validate_state(&self) -> Result<(), QRLError> {
        self.base.validate_state()?;
        let height = self.base.height as usize;
        let n = N as usize;
        if self.params.n != N
            || self.params.h != self.base.height as u32
            || self.params.k != BDS_K
            || self.state.stack.len() != (height + 1) * n
            || self.state.stacklevels.len() != height + 1
            || self.state.auth.len() != height * n
            || self.state.keep.len() != (height >> 1) * n
            || self.state.treehash.len() != height - BDS_K as usize
            || self
                .state
                .treehash
                .iter()
                .any(|treehash| treehash.node.len() != n)
            || self.state.retain.len() != ((1_usize << BDS_K) - BDS_K as usize - 1) * n
        {
            return Err(QRLError::InvalidArgument(
                "Invalid XMSS traversal state".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn initialize_tree(&mut self, wots_param_w_option: Option<u32>) -> Result<(), QRLError> {
        let wots_param_w = wots_param_w_option.unwrap_or(16);
        self.base.validate_state()?;
        if self.base.get_index() != 0 {
            return Err(QRLError::InvalidArgument(
                "Cannot reinitialize an XMSS tree after signing".to_owned(),
            ));
        }
        let mut tmp = Zeroizing::new(vec![0; 64]);

        let k: u32 = BDS_K;
        let w: u32 = wots_param_w;
        let n: u32 = N;
        let height = self.base.height as u32;

        self.params = XMSSParams::new(n, height, w, k)?;

        let stackoffset = 0;
        let stack = vec![0; ((height + 1) * n) as usize];
        let stacklevels = vec![0; (height + 1) as usize];
        let auth = vec![0; (height * n) as usize];
        let keep = vec![0; ((height as u8 >> 1) as u32 * n) as usize];
        let mut treehash: Vec<TreeHashInst> =
            (0..height - k).map(|_| TreeHashInst::default()).collect();
        let retain = vec![0; (((1_u32 << k) - k - 1) * n) as usize];

        for i in 0..(height - k) as usize {
            treehash[i].node = vec![0; n as usize];
        }

        self.state = BDSState {
            stack,
            stackoffset,
            stacklevels,
            auth,
            keep,
            treehash,
            retain,
            next_leaf: 0,
        };

        xmss_fast_gen_keypair(
            &self.base.hash_function,
            &self.params,
            tmp.as_mut_slice(),
            &mut self.base.sk,
            &mut self.state,
            &mut self.base.seed,
        )?;
        self.validate_state()
    }

    pub fn new(
        seed: TSEED,
        height: u8,
        hash_function_option: Option<HashFunction>,
        addr_format_type_option: Option<AddrFormatType>,
        wots_param_w_option: Option<u32>,
    ) -> Result<Self, QRLError> {
        let mut seed = Zeroizing::new(seed);
        // FIXME: At the moment, the lib takes 48 bytes from the seed vector
        if seed.len() != 48 {
            return Err(QRLError::InvalidArgument(
                "Seed should be 48 bytes. Other values are not currently supported".to_owned(),
            ));
        }

        let hash_function = hash_function_option.unwrap_or(HashFunction::Shake128);
        let addr_format_type = addr_format_type_option.unwrap_or(AddrFormatType::SHA256_2X);
        let params = XMSSParams::default();
        let sk: TKEY = vec![0; Self::SECRET_KEY_SIZE];
        let base = XMSSBase::new(
            hash_function,
            addr_format_type,
            height,
            sk,
            std::mem::take(&mut *seed),
        )?;
        let state = BDSState::default();
        let mut xmss_fast = XMSSFast {
            base,
            params,
            state,
        };
        xmss_fast.initialize_tree(wots_param_w_option)?;
        return Ok(xmss_fast);
    }

    pub fn from_extended_seed(extended_seed: &TSEED) -> Result<Self, QRLError> {
        let sk: TKEY = vec![0; Self::SECRET_KEY_SIZE];
        let base = XMSSBase::from_extended_seed(extended_seed, sk)?;
        let params = XMSSParams::default();
        let state = BDSState::default();
        let mut xmss_fast = XMSSFast {
            base,
            params,
            state,
        };
        xmss_fast.initialize_tree(None)?;
        return Ok(xmss_fast);
    }
}

impl XMSSBaseTrait for XMSSFast {
    fn get_height(&self) -> u8 {
        self.base.get_height()
    }

    fn get_seed(&self) -> &TSEED {
        self.base.get_seed()
    }

    fn hash_function(&self) -> &HashFunction {
        self.base.hash_function()
    }

    fn addr_format_type(&self) -> &AddrFormatType {
        self.base.addr_format_type()
    }

    fn get_sk(&self) -> &TKEY {
        self.base.get_sk()
    }

    fn set_index(&mut self, new_index: u32) -> Result<u32, QRLError> {
        self.validate_state()?;
        let current_index = self.base.get_index();
        let exhausted_index = signature_count(self.base.height)?;
        if new_index > exhausted_index {
            return Err(QRLError::InvalidArgument("index too high".to_owned()));
        }
        if new_index < current_index {
            return Err(QRLError::InvalidArgument("cannot rewind".to_owned()));
        }
        let status = xmss_fast_update(
            &self.base.hash_function,
            &self.params,
            &mut self.base.sk,
            &mut self.state,
            new_index,
        )?;
        if status != 0 {
            return Err(QRLError::InvalidArgument(
                "XMSS state update failed".to_owned(),
            ));
        }
        Ok(new_index)
    }
}

impl Sign for XMSSFast {
    fn sign(&mut self, message: &TMESSAGE) -> Result<TSIGNATURE, QRLError> {
        self.validate_state()?;
        if self.base.get_index() >= signature_count(self.base.height)? {
            return Err(QRLError::InvalidArgument("index too high".to_owned()));
        }
        let mut signature = Zeroizing::new(vec![
            0;
            self.get_signature_size(Some(self.params.wots_par.w))
                as usize
        ]);

        let status = xmss_fast_sign_msg(
            &self.base.hash_function,
            &self.params,
            &mut self.base.sk,
            &mut self.state,
            signature.as_mut_slice(),
            message,
            message.len(),
        );
        if status != 0 {
            return Err(QRLError::InvalidArgument("XMSS signing failed".to_owned()));
        }

        Ok(std::mem::take(&mut *signature))
    }
}
