// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use sha2::{Digest, Sha256};

pub fn sha2_256(input: &Vec<u8>) -> Vec<u8> {
    // create a Sha256 object
    let mut hasher = Sha256::new();

    // write input message
    hasher.update(input.as_slice());

    // read hash digest and consume hasher
    Vec::from(hasher.finalize().as_slice())
}
