use super::{
    qrl_address_format::AddrFormatType,
    xmss_base::{Sign, XMSSBase, XMSSBaseTrait, TKEY, TMESSAGE, TSEED, TSIGNATURE},
};
use crate::rust_wrapper::xmss_alt::algsxmss::xmss_gen_keypair;
use crate::rust_wrapper::xmss_alt::algsxmss::xmss_sign_msg;
use crate::rust_wrapper::{
    errors::QRLError,
    xmss_alt::{hash_functions::HashFunction, xmss_common::XMSSParams},
};

pub struct XMSSBasic {
    base: XMSSBase,
    params: XMSSParams,
}

impl XMSSBasic {
    pub fn new(
        mut seed: TSEED,
        height: u8,
        hash_function: HashFunction,
        addr_format_type: AddrFormatType,
        wots_param_w_option: Option<u32>,
    ) -> Result<Self, QRLError> {
        //    PK format
        //    32 root address
        //    32 pub_seed
        //
        //    SK format
        //    4  idx
        //    32 sk_seed
        //    32 sk_prf
        //    32 pub_seed
        //    32 root

        let mut sk: TKEY = vec![0; Self::SECRET_KEY_SIZE];
        let mut tmp: TKEY = vec![0; 64];

        // FIXME: At the moment, the lib takes 48 bytes from the seed vector
        if seed.len() != 48 {
            return Err(QRLError::InvalidArgument(
                "Seed should be 48 bytes. Other values are not currently supported".to_owned(),
            ));
        }

        let k: u32 = 2;
        let w: u32 = wots_param_w_option.unwrap_or(16);
        let n: u32 = 32;

        if k >= height as u32 || (height as u32 - k) % 2 != 0 {
            return Err(QRLError::InvalidArgument(
                "For BDS traversal, H - K must be even, with H > K >= 2!".to_owned(),
            ));
        }

        let params = XMSSParams::new(n, height as u32, w, k)?;

        xmss_gen_keypair(&hash_function, &params, &mut tmp, &mut sk, &mut seed);

        let base = XMSSBase::new(hash_function, addr_format_type, height, sk, seed)?;
        Ok(Self { base, params })
    }
}

impl XMSSBaseTrait for XMSSBasic {
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
        self.base.set_index(new_index)
    }
}

impl Sign for XMSSBasic {
    fn sign(&mut self, message: &TMESSAGE) -> Result<TSIGNATURE, QRLError> {
        let mut signature: TSIGNATURE =
            vec![0; self.get_signature_size(Some(self.params.wots_par.w)) as usize];
        let message_len = message.len();
        xmss_sign_msg(
            &self.base.hash_function,
            &self.params,
            &mut self.base.sk,
            &mut signature,
            message,
            message_len,
        );

        return Ok(signature);
    }
}
