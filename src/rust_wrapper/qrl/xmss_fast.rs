use super::xmss_base::{Sign, XMSSBase, XMSSBaseTrait, TKEY, TMESSAGE, TSEED, TSIGNATURE};
use crate::rust_wrapper::errors::QRLError;
use crate::rust_wrapper::qrl::qrl_address_format::AddrFormatType;
use crate::rust_wrapper::xmss_alt::algsxmss_fast::{
    xmss_fast_gen_keypair, xmss_fast_sign_msg, xmss_fast_update, BDSState, TreeHashInst,
};
use crate::rust_wrapper::xmss_alt::hash_functions::HashFunction;
use crate::rust_wrapper::xmss_alt::xmss_common::XMSSParams;

pub struct XMSSFast {
    base: XMSSBase,
    params: XMSSParams,
    state: BDSState,
}

impl XMSSFast {
    pub fn initialize_tree(&mut self, wots_param_w_option: Option<u32>) -> Result<(), QRLError> {
        let wots_param_w = wots_param_w_option.unwrap_or(16);
        let mut tmp: TKEY = vec![0; 64];

        let k: u32 = 2;
        let w: u32 = wots_param_w;
        let n: u32 = 32;
        let height = self.base.height as u32;

        if k >= height as u32 || (height - k) % 2 != 0 {
            return Err(QRLError::InvalidArgument(
                "For BDS traversal, H - K must be even, with H > K >= 2!".to_owned(),
            ));
        }

        self.params = XMSSParams::new(n, height, w, k)?;

        let stackoffset = 0;
        let stack = vec![0; ((height + 1) * n) as usize];
        let stacklevels = vec![0; (height + 1) as usize];
        let auth = vec![0; (height * n) as usize];
        let keep = vec![0; ((height as u8 >> 1) as u32 * n) as usize];
        let mut treehash = vec![TreeHashInst::default(); (height - k) as usize];
        let retain = vec![0; (((1 << k) - k - 1) * n) as usize];

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
            &mut tmp,
            &mut self.base.sk,
            &mut self.state,
            &mut self.base.seed,
        )
    }

    pub fn new(
        seed: TSEED,
        height: u8,
        hash_function_option: Option<HashFunction>,
        addr_format_type_option: Option<AddrFormatType>,
        wots_param_w_option: Option<u32>,
    ) -> Result<Self, QRLError> {
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
        let base = XMSSBase::new(hash_function, addr_format_type, height, sk, seed)?;
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
        xmss_fast_update(
            &self.base.hash_function,
            &self.params,
            &mut self.base.sk,
            &mut self.state,
            new_index,
        )?;
        Ok(new_index)
    }
}

impl Sign for XMSSFast {
    fn sign(&mut self, message: &TMESSAGE) -> Result<TSIGNATURE, QRLError> {
        let mut signature: TSIGNATURE =
            vec![0; self.get_signature_size(Some(self.params.wots_par.w)) as usize];

        let index = self.base.get_index();
        self.set_index(index)?;

        xmss_fast_sign_msg(
            &self.base.hash_function,
            &self.params,
            &mut self.base.sk,
            &mut self.state,
            &mut signature,
            message,
            message.len(),
        );

        return Ok(signature);
    }
}
