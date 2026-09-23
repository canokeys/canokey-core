// SPDX-License-Identifier: Apache-2.0
use super::Error;
use crate::{Platform, applets::pass::service::Pass};
pub fn touch(pass: &Pass, index: u8, out: &mut [u8], p: &mut Platform<'_>) -> Result<usize, Error> {
    #[cfg(feature = "oath")]
    if let crate::applets::pass::domain::Slot::Oath { id, enter, .. } =
        pass.slot(index).map_err(Error::Pass)?
    {
        use crate::applets::oath::service;
        let mut store = crate::applets::oath::repository::Store::new(p.storage, p.memory);
        let mut mac = crate::applets::oath::repository::Mac::new(p.crypto, p.memory);
        // The physical gesture authorizes this output, independently of the OATH session.
        let mut result = service::calculate(
            &mut store,
            &mut mac,
            service::CredentialId(id),
            &[],
            service::Presence::Confirmed,
        )
        .map_err(Error::Oath)?;
        let digits = usize::from(result.digits());
        let length = digits + usize::from(enter != 0);
        if out.len() < length {
            result.clear(&mut mac);
            return Err(Error::Output);
        }
        let mut value = result.truncated();
        for byte in out[..digits].iter_mut().rev() {
            *byte = b'0' + (value % 10) as u8;
            value /= 10;
        }
        if enter != 0 {
            out[digits] = b'\r';
        }
        result.clear(&mut mac);
        return Ok(length);
    }
    let _ = p;
    pass.touch(index, out).map_err(Error::Pass)
}
