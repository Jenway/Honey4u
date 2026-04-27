use super::super::error::{DriverError, DriverResult};
use super::{HbPkePrivateKeyShare, HbPkePublicParams};
use honey_wire::codec::{decode_hex, json_string_field};
use honey_wire::crypto_wire::{PkePrivateKeyShareWire, PkePublicParamsWire};
use serde_json::Value;

pub(crate) fn parse_honeybadger_crypto_payload(
    payload: &str,
) -> DriverResult<(HbPkePublicParams, HbPkePrivateKeyShare)> {
    let decoded = serde_json::from_str::<Value>(payload)
        .map_err(|err| DriverError::config(err.to_string()))?;
    let public_key =
        decode_hex(json_string_field(&decoded, "enc_pk").map_err(DriverError::config)?)
            .map_err(DriverError::config)?;
    let private_share =
        decode_hex(json_string_field(&decoded, "enc_sk").map_err(DriverError::config)?)
            .map_err(DriverError::config)?;
    Ok((
        decode_pke_public_params(&public_key)?,
        decode_pke_private_share(&private_share)?,
    ))
}

fn decode_pke_public_params(payload: &[u8]) -> DriverResult<HbPkePublicParams> {
    let wire: PkePublicParamsWire =
        honey_wire::api::decode_result(payload).map_err(DriverError::serialization)?;
    wire.into_runtime()
        .map_err(DriverError::honey_badger_crypto)
}

fn decode_pke_private_share(payload: &[u8]) -> DriverResult<HbPkePrivateKeyShare> {
    let wire: PkePrivateKeyShareWire =
        honey_wire::api::decode_result(payload).map_err(DriverError::serialization)?;
    wire.into_runtime()
        .map_err(DriverError::honey_badger_crypto)
}
