use super::{
    qrl_address_format::AddrFormatType,
    qrl_descriptor::{QRLDescriptor, SignatureType},
    qrl_helper::get_address as get_address_helper,
};
use crate::rust_wrapper::{
    errors::QRLError,
    xmss_alt::{
        hash_functions::HashFunction,
        wots::WOTSParams,
        xmss_common::{xmss_verify_sig, XMSSParams},
    },
};

pub type TSIGNATURE = Vec<u8>;
pub type TMESSAGE = Vec<u8>;
pub type TSEED = Vec<u8>;
pub type TKEY = Vec<u8>;

// TODO: Use a union? to operate on partial fields
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

//const SIGNATURE_BASE_SIZE: usize  = 4+32+67*32;

const XMSS_MAX_HEIGHT: usize = 254;

// FIXME: Use a union for this
const OFFSET_IDX: usize = 0;

const OFFSET_SK_SEED: usize = OFFSET_IDX + 4;

const OFFSET_SK_PRF: usize = OFFSET_SK_SEED + 32;

const OFFSET_PUB_SEED: usize = OFFSET_SK_PRF + 32;

const OFFSET_ROOT: usize = OFFSET_PUB_SEED + 32;

pub struct XMSSBase {
    pub hash_function: HashFunction,
    pub addr_format_type: AddrFormatType,
    pub height: u8,
    pub sk: TKEY,
    pub seed: TSEED,
}

impl XMSSBase {
    pub fn new(
        hash_function: HashFunction,
        addr_format_type: AddrFormatType,
        height: u8,
        sk: TKEY,
        seed: TSEED,
    ) -> Result<Self, QRLError> {
        if seed.len() != 48 {
            Err(QRLError::InvalidArgument(
                "Seed should be 48 bytes. Other values are not currently supported".to_owned(),
            ))
        } else if height as usize > XMSS_MAX_HEIGHT {
            Err(QRLError::InvalidArgument(
                "Height should be <= 254".to_owned(),
            ))
        } else {
            Ok(Self {
                hash_function,
                addr_format_type,
                height,
                sk,
                seed,
            })
        }
    }

    pub fn from_extended_seed(extended_seed: &TSEED, sk: TKEY) -> Result<Self, QRLError> {
        if extended_seed.len() != 51 {
            return Err(QRLError::InvalidArgument(
                "Extended seed should be 51 bytes. Other values are not currently supported"
                    .to_owned(),
            ));
        }

        let desc = QRLDescriptor::from_extended_seed(extended_seed)?;

        let seed = extended_seed[QRLDescriptor::get_size() as usize..extended_seed.len()].to_vec();

        let height = desc.get_height();
        let hash_function = desc.get_hash_function().to_owned();
        let addr_format_type = desc.get_addr_format_type().to_owned();
        Ok(Self {
            hash_function,
            addr_format_type,
            height,
            sk,
            seed,
        })
    }
}

impl XMSSBaseTrait for XMSSBase {
    fn get_height(&self) -> u8 {
        self.height
    }

    fn get_seed(&self) -> &TSEED {
        &self.seed
    }

    fn hash_function(&self) -> &HashFunction {
        &self.hash_function
    }

    fn addr_format_type(&self) -> &AddrFormatType {
        &self.addr_format_type
    }

    fn get_sk(&self) -> &TKEY {
        &self.sk
    }

    fn set_index(&mut self, mut new_index: u32) -> Result<u32, QRLError> {
        self.sk[3] = (new_index & 0xFF) as u8;
        new_index >>= 8;
        self.sk[2] = (new_index & 0xFF) as u8;
        new_index >>= 8;
        self.sk[1] = (new_index & 0xFF) as u8;
        new_index >>= 8;
        self.sk[0] = (new_index & 0xFF) as u8;

        Ok(self.get_index())
    }
}

pub trait XMSSBaseTrait {
    const SECRET_KEY_SIZE: usize = 132;
    const PUBLIC_KEY_SIZE: usize = QRLDescriptor::get_size() as usize + 64;

    fn calculate_signature_base_size(wots_param_w: Option<u32>) -> u32 {
        let w = wots_param_w.unwrap_or(16);
        let wots_params = WOTSParams::new(32, w);
        4 + 32 + wots_params.keysize
    }

    fn get_signature_size(&self, wots_param_w: Option<u32>) -> u32 {
        let signature_base_size = Self::calculate_signature_base_size(wots_param_w);
        // 4 + n + (len + h) * n)
        signature_base_size + self.get_height() as u32 * 32
    }

    fn get_height_from_sig_size(
        sig_size: usize,
        wots_param_w: Option<u32>,
    ) -> Result<u8, QRLError> {
        let signature_base_size = Self::calculate_signature_base_size(wots_param_w) as usize;
        if sig_size < signature_base_size {
            return Err(QRLError::InvalidArgument(
                "Invalid signature size".to_owned(),
            ));
        }

        if (sig_size - 4) % 32 != 0 {
            return Err(QRLError::InvalidArgument(
                "Invalid signature size".to_owned(),
            ));
        }

        let height = (sig_size - signature_base_size) / 32;

        Ok(height as u8)
    }

    fn get_public_key_size() -> usize {
        Self::PUBLIC_KEY_SIZE
    }

    fn get_secret_key_size() -> usize {
        Self::SECRET_KEY_SIZE
    }

    fn get_sk_seed(&self) -> TKEY {
        // FIXME: Use a union for this
        self.get_sk()[OFFSET_SK_SEED..OFFSET_SK_SEED + 32].to_vec()
    }

    fn get_sk_prf(&self) -> TKEY {
        // FIXME: Use a union for this
        self.get_sk()[OFFSET_SK_PRF..OFFSET_SK_PRF + 32].to_vec()
    }

    fn get_pk_seed(&self) -> TKEY {
        // FIXME: Use a union for this
        self.get_sk()[OFFSET_PUB_SEED..OFFSET_PUB_SEED + 32].to_vec()
    }

    fn get_root(&self) -> TKEY {
        // FIXME: Use a union for this
        self.get_sk()[OFFSET_ROOT..OFFSET_ROOT + 32].to_vec()
    }

    fn get_index(&self) -> u32 {
        let sk = self.get_sk();
        ((sk[0] as u32) << 24) + ((sk[1] as u32) << 16) + ((sk[2] as u32) << 8) + (sk[3] as u32)
    }

    fn set_index(&mut self, new_index: u32) -> Result<u32, QRLError>;

    fn get_sk(&self) -> &TKEY;

    fn get_descriptor(&self) -> QRLDescriptor {
        QRLDescriptor::new(
            *self.hash_function(),
            SignatureType::XMSS,
            self.get_height(),
            *self.addr_format_type(),
        )
    }

    fn get_descriptor_bytes(&self) -> Vec<u8> {
        self.get_descriptor().get_bytes()
    }

    fn get_pk(&self) -> TKEY {
        //    PK format
        //     3 QRL_DESCRIPTOR
        //    32 root address
        //    32 pub_seed

        // TODO: Improve and avoid copies / recalculation
        let mut pk: TKEY = self.get_descriptor_bytes();
        let root = self.get_root();
        let pubseed = self.get_pk_seed();
        pk.extend(root);
        pk.extend(pubseed);

        pk
    }

    fn get_extended_seed(&self) -> TSEED {
        let mut extended_seed: TKEY = self.get_descriptor_bytes();
        extended_seed.extend(self.get_seed().clone());
        extended_seed
    }

    fn get_address(&self) -> Result<Vec<u8>, QRLError> {
        get_address_helper(&self.get_pk())
    }

    fn verify(
        message: &mut TMESSAGE,
        signature: &TSIGNATURE,
        extended_pk: &TKEY,
        wots_param_w: Option<u32>,
    ) -> Result<(), QRLError> {
        if extended_pk.len() != 67 {
            return Err(QRLError::InvalidArgument(
                "Invalid extended_pk size. It should be 67 bytes".to_owned(),
            ));
        }
        let signature_base_size: usize = Self::calculate_signature_base_size(wots_param_w) as usize;
        if signature.len() > signature_base_size + XMSS_MAX_HEIGHT * 32 {
            return Err(QRLError::InvalidArgument(
                "invalid signature size. Height<=254".to_owned(),
            ));
        }

        let desc = QRLDescriptor::from_extended_pk(extended_pk)?;
        if *desc.get_signature_type() != SignatureType::XMSS {
            return Err(QRLError::InvalidArgument(
                "Invalid signature type".to_owned(),
            ));
        }

        let height = Self::get_height_from_sig_size(signature.len(), wots_param_w)?;

        if height == 0 || desc.get_height() != height {
            return Err(QRLError::InvalidArgument(
                "Invalid height from sig size".to_owned(),
            ));
        }

        let hash_function = desc.get_hash_function();

        let k: u32 = 2;
        let w: u32 = wots_param_w.unwrap_or(16);
        let n: u32 = 32;

        if k >= height as u32 || (height as u32 - k) % 2 != 0 {
            return Err(QRLError::InvalidArgument(
                "For BDS traversal, H - K must be even, with H > K >= 2!".to_owned(),
            ));
        }

        let params = XMSSParams::new(n, height.into(), w, k)?;

        let verify_pk = &extended_pk[QRLDescriptor::get_size() as usize..extended_pk.len()];
        let message_len = message.len();
        if xmss_verify_sig(
            hash_function,
            &params.wots_par,
            message,
            message_len,
            signature,
            verify_pk,
            height,
        ) == 0
        {
            Ok(())
        } else {
            Err(QRLError::InvalidArgument("Failed verification".to_owned()))
        }
    }

    fn get_height(&self) -> u8;

    fn get_seed(&self) -> &TSEED;

    fn get_number_signatures(&self) -> u32 {
        1 << self.get_height()
    }

    fn get_remaining_signatures(&self) -> u32 {
        self.get_number_signatures() - self.get_index()
    }

    fn hash_function(&self) -> &HashFunction;

    fn addr_format_type(&self) -> &AddrFormatType;
}

pub trait Sign {
    fn sign(&mut self, message: &TMESSAGE) -> Result<TSIGNATURE, QRLError>;
}
