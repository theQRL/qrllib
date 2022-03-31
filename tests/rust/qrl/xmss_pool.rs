use hex::encode;
use qrllib::rust_wrapper::qrl::qrl_address_format::AddrFormatType;
use qrllib::rust_wrapper::qrl::qrl_helper;
use qrllib::rust_wrapper::qrl::xmss_base::XMSSBase;
use qrllib::rust_wrapper::qrl::xmss_base::XMSSBaseTrait;
use qrllib::rust_wrapper::qrl::xmss_base::TKEY;
use qrllib::rust_wrapper::qrl::xmss_base::TMESSAGE;
use qrllib::rust_wrapper::qrl::xmss_base::TSIGNATURE;
use qrllib::rust_wrapper::qrl::xmss_basic::XMSSBasic;
use qrllib::rust_wrapper::qrl::xmss_fast::XMSSFast;
use qrllib::rust_wrapper::qrl::xmss_pool::XMSSPool;
use qrllib::rust_wrapper::xmss_alt::hash_functions::HashFunction;

const pks: [&str; 5] =
            [
                    "0103002dcc3803df4475334b29eaa2516d1a9b36bc19eed0542cfbb501bf8de95d939b25510d9876c7845b4694441bdc0e2be51f3d3f87f0c7775893845f25d49f9ef1",
                    "010300be9caeafe11fa52edf722063c18616d6d0c6c30dba3e2c9369a6d9260f76818bc424a1b6db5f26ef01ffa4aac8a08440d6a569bc56180b06f51b6ff6e4cc1b2e",
                    "0103005deb91b1d311ecc8c6954e22f3e140ff3e6c04e40cad50c940e60abba3cf766a5db9f39f58e532bea6765e4530cb581db1d6afbb7c05da3261ca4db21177afc5",
                    "010300ea15c686e7b9691b8bac52ee4d0ed33bd75ec600f55b4476b857858460c2c98390712040a5e03bca7a46715a90270ac2f8db8694ffa943091edb9018fa1dda04",
                    "010300cc9aa42776ce6d286003055b793223002acb42f7e6c27773dabfd54960bb7d9d1dc356395528c65ff6f444aae130176c213718dd5c4a39858ca150031fb2451e"
            ];

#[test]
fn instantiation() {
    let baseseed: Vec<u8> = vec![0; 48];

    let height = 6;
    let starting_index = 0;
    let pool_size = 0;
    println!();

    let mut pool: XMSSPool = XMSSPool::new(baseseed, height, starting_index, pool_size).unwrap();
    for i in 0..5 {
        assert_eq!(pool.get_current_index(), i);
        let xmss = pool.get_next_tree().unwrap();
        assert_eq!(pks[i], encode(&xmss.base.get_pk()));
    }
}

#[test]
fn instantiation_2() {
    let baseseed: Vec<u8> = vec![0; 48];

    let height = 6;
    let starting_index = 0;
    let pool_size = 5;
    println!();

    let mut pool: XMSSPool = XMSSPool::new(baseseed, height, starting_index, pool_size).unwrap();
    for i in 0..5 {
        assert_eq!(pool.get_current_index(), i);
        let xmss = pool.get_next_tree().unwrap();
        assert_eq!(pks[i], encode(&xmss.base.get_pk()));
    }
}

#[test]
fn instantiation_3() {
    let baseseed: Vec<u8> = vec![0; 48];

    let height = 6;
    let starting_index = 1;
    let pool_size = 4;
    println!();

    let mut pool: XMSSPool = XMSSPool::new(baseseed, height, starting_index, pool_size).unwrap();
    for i in 1..5 {
        assert_eq!(pool.get_current_index(), i);
        let xmss = pool.get_next_tree().unwrap();
        assert_eq!(pks[i], encode(&xmss.base.get_pk()));
    }
}
