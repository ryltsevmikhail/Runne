//! Candidate-only feature guarantee: baseline did not promise AES schedule wipe.
use super::*;

#[test]
fn selected_aes_and_cbc_types_have_zeroize_on_drop_guarantees() {
    fn protected<T: zeroize::ZeroizeOnDrop>() {}
    protected::<aes::Aes128>();
    protected::<Aes128CbcEnc>();
    protected::<Aes128CbcDec>();
    protected::<Zeroizing<Vec<u8>>>();
    protected::<Zeroizing<[u8; 16]>>();
}
