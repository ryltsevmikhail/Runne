use crate::SecureStoreError;

/// Index order: Primary, Alternate, migration backup. The caller owns the lock.
pub fn inspect(
    mut present: impl FnMut(usize) -> Result<bool, SecureStoreError>,
) -> Result<bool, SecureStoreError> {
    let mut any = false;
    for slot in 0..3 {
        any |= present(slot)?;
    }
    Ok(any)
}
