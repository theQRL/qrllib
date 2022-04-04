use qrllib::rust_wrapper::qrl::hashing;
use qrllib::rust_wrapper::qrl::misc;

#[test]
fn bin2hstr() {
    let data: Vec<u8> = vec![1, 2];

    assert_eq!(data.len(), 2);
    assert_eq!(misc::bin2hstr(&data, 4), "0102");

    // Note that "5" is missing
    let data_long: Vec<u8> = vec![0, 1, 2, 3, 4, 6, 7, 8];
    assert_eq!(data_long.len(), 8);
    assert_eq!(misc::bin2hstr(&data_long, 4), "00010203\n04060708");
    assert_eq!(misc::bin2hstr(&data_long, 8), "0001020304060708");
}

#[test]
fn hstr2bin() {
    assert_eq!(misc::hstr2bin(&"10".to_owned()).unwrap(), vec![0x10]);
    assert_eq!(
        misc::hstr2bin(&"102aAB".to_owned()).unwrap(),
        vec![0x10, 0x2a, 0xab]
    );
}

#[test]
fn bin2mnemonic_empty() {
    let input = Vec::new();
    let mnemonic = misc::bin2mnemonic(&input).unwrap();
    assert_eq!(mnemonic, "");
}

#[test]
fn bin2mnemonic_3_bytes() {
    let input = vec![0x00, 0x00, 0x00];
    let mnemonic = misc::bin2mnemonic(&input).unwrap();
    assert_eq!(mnemonic, "aback aback");
}

#[test]
fn bin2mnemonic_3_bytes_b() {
    let input = vec![0x00, 0x01, 0x00];
    let mnemonic = misc::bin2mnemonic(&input).unwrap();
    assert_eq!(mnemonic, "aback badge");
}

#[test]
fn bin2mnemonic_3_bytes_c() {
    let input = vec![0x00, 0x02, 0x00];
    let mnemonic = misc::bin2mnemonic(&input).unwrap();
    assert_eq!(mnemonic, "aback bunny");
}

#[test]
fn bin2mnemonic_4_bytes_a() {
    let input = vec![0x12, 0x34, 0x56, 0x78];
    assert!(misc::bin2mnemonic(&input).is_err());
}

#[test]
fn bin2mnemonic_5_bytes_b() {
    let input = vec![0x12, 0x34, 0x56, 0x78, 0x00];
    assert!(misc::bin2mnemonic(&input).is_err());
}

#[test]
fn bin2mnemonic_6_bytes_a() {
    let input = vec![0x12, 0x34, 0x56, 0x78, 0x01, 0x00];
    let mnemonic = misc::bin2mnemonic(&input).unwrap();
    assert_eq!(mnemonic, "base elbow knew badge");
}

#[test]
fn bin2mnemonic_6_bytes_b() {
    let input = vec![0x12, 0x34, 0x56, 0x78, 0x01, 0x09];
    let mnemonic = misc::bin2mnemonic(&input).unwrap();
    assert_eq!(mnemonic, "base elbow knew bald");
}

#[test]
fn mnemonic2bin_simple1() {
    let input = "base elbow knew aback bag bunny".to_string();
    let data = misc::mnemonic2bin(&input).unwrap();
    assert_eq!(misc::bin2hstr(&data, 0), "123456780000102200");
}

#[test]
fn mnemonic2bin_simple2() {
    let input = "base elbow knew bag".to_string();
    let data = misc::mnemonic2bin(&input).unwrap();
    assert_eq!(misc::bin2hstr(&data, 0), "123456780102");
}

#[test]
fn mnemonic2bin_unknown() {
    let input = "base elbow knew unknown".to_string();
    assert!(misc::mnemonic2bin(&input).is_err());
}

#[test]
fn mnemonic2bin_long() {
    let input =
        "law bruise screen lunar than loft but franc strike asleep dwarf tavern dragon alarm 
    snack queen meadow thing far cotton add emblem strive probe zurich edge peer alight 
    libel won corn medal"
            .to_string();
    let data = misc::mnemonic2bin(&input).unwrap();
    assert_eq!(misc::bin2hstr(&data, 0), "7ad1e6c1083de2081221056dd8b0c142cdfa3fd053cd4ae288ee324cd30e027462d8eaaffff445a1105b7e4fc1302894");
}

#[test]
fn mnemonic2bin_wrongword() {
    let input = "basin xxWRONGxx".to_string();
    assert!(misc::mnemonic2bin(&input).is_err());
}

#[test]
fn get_hash_chain_seed() {
    let input = "This is a test X".to_string();
    let input_bin = misc::str2bin(&input);
    let initial_seed = hashing::shake256(32, &input_bin);

    let r = misc::get_hash_chain_seed(&initial_seed, 10, 10);
    assert_eq!(r.len(), 10);

    assert_eq!(
        misc::bin2hstr(&r[0], 0),
        "51971ec39522177c33a60b915fbf8fb21570018444fbe63692b13438fdceaad0"
    );
    assert_eq!(
        misc::bin2hstr(&r[1], 0),
        "9920072f88d306b4a6ac7089ce9917987e39c78945cce698ed94f709c733dc06"
    );
    assert_eq!(
        misc::bin2hstr(&r[2], 0),
        "c328fcaceec93d7154f4bdca0e47a7879ab818155f21408c5b102e08bbb025ca"
    );
    assert_eq!(
        misc::bin2hstr(&r[3], 0),
        "75fe0b40f93d78f8de2fd133c03ab54fb03c2d3ddd79902e21107ad46430012b"
    );
    assert_eq!(
        misc::bin2hstr(&r[4], 0),
        "e8f521172ac2539f298d31338135d7095fd0c6893757ec4b6a3ae466c234f3ad"
    );
    assert_eq!(
        misc::bin2hstr(&r[5], 0),
        "3711e7b57f9c6f5260f94f0d6f6c0f8d7058e1178e33fa66ffb44c59f80b2fbd"
    );
    assert_eq!(
        misc::bin2hstr(&r[6], 0),
        "159acf444f864cceebf45af42aa10d9045f022e5cad53937d8fcfe448430f02d"
    );
    assert_eq!(
        misc::bin2hstr(&r[7], 0),
        "def097a0ba2de30f98f88188de84b0f6db41e70dbde8e6d93b4ec6afa6fa319c"
    );
    assert_eq!(
        misc::bin2hstr(&r[8], 0),
        "ab10d7e3a6c6a782143d864606a4cd6f70147c7c203528b2af2dbd409dde0f02"
    );
    assert_eq!(
        misc::bin2hstr(&r[9], 0),
        "a1083ac97a92ba4a86a37f09a018e5ef1db29e80e007224effdd8bbcafe7445b"
    );
}
