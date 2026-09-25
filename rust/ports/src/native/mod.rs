// SPDX-License-Identifier: Apache-2.0
//! One implementation serves direct firmware calls and trait-based host tests.
//! Only this adapter layer crosses the native ABI.
macro_rules! native_port {
    (impl $trait:ident for $backend:ident {
        $( $(#[$attr:meta])* fn $method:ident(&mut self $(, $arg:ident: $ty:ty)* $(,)?)
            $(-> $result:ty)? $body:block )*
    }) => {
        impl $backend {
            $( $(#[$attr])* pub fn $method(&mut self $(, $arg: $ty)*)
                $(-> $result)? $body )*
        }
        impl $trait for $backend {
            $( $(#[$attr])* fn $method(&mut self $(, $arg: $ty)*) $(-> $result)? {
                $backend::$method(self $(, $arg)*)
            } )*
        }
    };
}
mod crypto;
mod storage;
pub use crypto::CryptoBackend;
pub use storage::StorageBackend;

mod device;
pub use device::{DeviceBackend, MemoryBackend};
