// SPDX-License-Identifier: Apache-2.0
// Product GetInfo composition over the shared schema builder.
pub fn generate_info(firmware: u32) {
    use canokey_ctap::{
        info::{Flag, Value},
        schema::Builder,
    };
    let restricted = std::env::var_os("CARGO_FEATURE_CTAP_RESTRICT_ALGORITHMS").is_some();
    let nfc = std::env::var_os("CARGO_FEATURE_CTAP_NFC").is_some();
    let mut schema = Builder::new();
    schema.choice(
        Flag::ForceChange,
        |e| {
            e.map(22)?.u8(1)?;
            Ok(())
        },
        |e| {
            e.map(21)?.u8(1)?;
            Ok(())
        },
    );
    schema.choice(
        Flag::AlwaysUv,
        |e| {
            e.array(3)?;
            Ok(())
        },
        |e| {
            e.array(4)?.str("U2F_V2")?;
            Ok(())
        },
    );
    schema.encoded(|e| {
        e.str("FIDO_2_0")?
            .str("FIDO_2_1")?
            .str("FIDO_2_3")?
            .u8(2)?
            .array(7)?
            .str("credBlob")?
            .str("credProtect")?
            .str("hmac-secret")?
            .str("hmac-secret-mc")?
            .str("largeBlobKey")?
            .str("minPinLength")?
            .str("thirdPartyPayment")?
            .u8(3)?;
        Ok(())
    });
    schema.value(Value::Aaguid);
    schema.encoded(|e| {
        e.u8(4)?.map(9)?.str("rk")?.bool(true)?.str("alwaysUv")?;
        Ok(())
    });
    schema.value(Value::AlwaysUv);
    schema.encoded(|e| {
        e.str("credMgmt")?
            .bool(true)?
            .str("authnrCfg")?
            .bool(true)?
            .str("clientPin")?;
        Ok(())
    });
    schema.value(Value::ClientPin);
    schema.encoded(|e| {
        e.str("largeBlobs")?
            .bool(true)?
            .str("pinUvAuthToken")?
            .bool(true)?
            .str("setMinPINLength")?
            .bool(true)?
            .str("makeCredUvNotRqd")?;
        Ok(())
    });
    schema.value(Value::MakeCredUvNotRqd);
    schema.encoded(|e| {
        e.u8(5)?
            .u16(crate::config::CTAP_MAX_REQUEST as u16)?
            .u8(6)?
            .array(2)?
            .u8(1)?
            .u8(2)?
            .u8(7)?
            .u8(16)?
            .u8(8)?
            .u8(34)?
            .u8(9)?;
        if nfc {
            e.array(2)?.str("nfc")?.str("usb")?;
        } else {
            e.array(1)?.str("usb")?;
        }
        let pq = canokey_ports::mldsa::PARAMETER_SETS;
        e.u8(10)?
            .array(if restricted { 2 } else { 3 + pq.len() as u64 })?;
        for algorithm in [-7, -8]
            .into_iter()
            .chain(pq.into_iter().filter(|_| !restricted).map(|p| p.cose))
        {
            e.map(2)?
                .str("alg")?
                .i32(algorithm)?
                .str("type")?
                .str("public-key")?;
        }
        if !restricted {
            e.map(2)?.str("alg")?;
        }
        Ok(())
    });
    if !restricted {
        schema.value(Value::Algorithm);
    }
    schema.encoded(|e| {
        if !restricted {
            e.str("type")?.str("public-key")?;
        }
        e.u8(11)?.u16(4096)?;
        Ok(())
    });
    schema.choice(
        Flag::ForceChange,
        |e| {
            e.u8(12)?.bool(true)?;
            Ok(())
        },
        |_| Ok(()),
    );
    schema.encoded(|e| {
        e.u8(13)?;
        Ok(())
    });
    schema.value(Value::MinimumPinLength);
    schema.encoded(|e| {
        e.u8(14)?
            .u32(firmware)?
            .u8(15)?
            .u8(32)?
            .u8(16)?
            .u8(4)?
            .u8(20)?;
        Ok(())
    });
    schema.value(Value::RemainingCredentials);
    schema.encoded(|e| {
        e.u8(22)?.array(1)?.str("packed")?.u8(24)?;
        Ok(())
    });
    schema.value(Value::LongReset);
    schema.encoded(|e| {
        e.u8(26)?
            .array(2)?
            .str("nfc")?
            .str("usb")?
            .u8(29)?
            .u8(63)?
            .u8(31)?
            .array(3)?
            .u8(2)?
            .u8(3)?
            .u8(4)?;
        Ok(())
    });
    let path = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(path.join("ctap_info.rs"), schema.source()).unwrap();
}
