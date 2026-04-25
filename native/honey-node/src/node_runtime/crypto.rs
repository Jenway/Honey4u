use crate::codec::{decode_hex, json_string_field};
use honey_node::hb::{
    HbPkePrivateKeyShare, HbPkePublicParams, decode_pke_private_share, decode_pke_public_params,
};
use serde_json::Value;

pub(crate) fn parse_honeybadger_crypto_payload(
    payload: &str,
) -> Result<(HbPkePublicParams, HbPkePrivateKeyShare), String> {
    let decoded = serde_json::from_str::<Value>(payload).map_err(|err| err.to_string())?;
    let public_key = decode_hex(json_string_field(&decoded, "enc_pk")?)?;
    let private_share = decode_hex(json_string_field(&decoded, "enc_sk")?)?;
    Ok((
        decode_pke_public_params(&public_key)?,
        decode_pke_private_share(&private_share)?,
    ))
}
