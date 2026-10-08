// SPDX-License-Identifier: Apache-2.0
//! OATH mutations coordinated with durable PASS credential references.
use crate::{
    Platform,
    applets::{
        oath::{
            self,
            credential::Kind,
            repository::{Mac, Store},
            service::{self, Repository},
        },
        pass::{
            domain::{self, Slot, SlotIndex},
            service::Pass,
        },
    },
};

pub(crate) enum Error {
    Oath(oath::Error),
    Pass(domain::Error),
    NotHotp,
}

pub(crate) fn delete(
    name: &[u8],
    pass: Option<&mut Pass>,
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<(), Error> {
    let id = service::find(
        &mut Store::new(p.storage, p.memory),
        &mut Mac::new(p.crypto, p.memory),
        name,
    )
    .map_err(Error::Oath)?;
    // Unlink first: an erased/reused OATH record must never reactivate a slot.
    if let Some(pass) = pass {
        pass.remove_oath(Some(id.0), p.storage, p.memory)
            .map_err(Error::Pass)?;
    }
    Store::new(p.storage, p.memory)
        .delete(id)
        .map_err(Error::Oath)
}

pub(crate) fn bind(
    pass: &mut Pass,
    index: SlotIndex,
    name: &[u8],
    enter: u8,
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<(), Error> {
    let mut store = Store::new(p.storage, p.memory);
    let id =
        service::find(&mut store, &mut Mac::new(p.crypto, p.memory), name).map_err(Error::Oath)?;
    if store.credential_kind(id).map_err(Error::Oath)? != Kind::Hotp {
        return Err(Error::NotHotp);
    }
    // Binding needs only metadata; do not read a credential's secret key.
    pass.configure(
        index,
        Slot::Oath {
            id: id.0,
            name,
            enter,
        },
        p.storage,
        p.memory,
    )
    .map_err(Error::Pass)
}
