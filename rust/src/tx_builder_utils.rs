use super::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
use js_sys::*;
#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
use serde_json::{Map, Value as Val};
#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
use wasm_bindgen::JsCast;
#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
use wasm_bindgen_futures::JsFuture;
#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
use web_sys::{Request, RequestInit, Response};

// creates a custom window object to parse the fetch API from JavaScript into Rust;
#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen]
    pub type globalThis;

    # [wasm_bindgen (structural , method , getter , js_name = global)]
    pub fn global(this: &globalThis) -> globalThis;

    # [wasm_bindgen (structural , method , getter , js_name = self)]
    pub fn self_(this: &globalThis) -> globalThis;

    # [wasm_bindgen (method , structural, js_name = fetch)]
    pub fn fetch_with_request(this: &globalThis, input: &web_sys::Request) -> ::js_sys::Promise;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RedeemerResult {
    pub result: Option<EvaluationResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub EvaluationResult: Option<HashMap<String, ExUnitResult>>,
    pub EvaluationFailure: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExUnitResult {
    pub memory: u64,
    pub steps: u64,
}

#[wasm_bindgen]
#[derive(
    Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize, JsonSchema,
)]
pub struct Blockfrost {
    url: String,
    project_id: String,
}

#[wasm_bindgen]
impl Blockfrost {
    pub fn new(url: String, project_id: String) -> Self {
        Self {
            url: url.clone(),
            project_id: project_id.clone(),
        }
    }
    pub fn url(&self) -> String {
        self.url.clone()
    }
    pub fn project_id(&self) -> String {
        self.project_id.clone()
    }
}

#[cfg(not(all(target_arch = "wasm32", not(target_os = "emscripten"))))]
pub async fn get_ex_units(tx: Transaction, bf: &Blockfrost) -> Result<Redeemers, JsError> {
    Ok(Redeemers::new())
}

#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
pub async fn get_ex_units(tx: Transaction, bf: &Blockfrost) -> Result<Redeemers, JsError> {
    if bf.url.is_empty() || bf.project_id.is_empty() {
        return Err(JsError::from_str(
            "Blockfrost not set. Can't calculate ex units",
        ));
    }

    let mut opts = RequestInit::new();
    opts.method("POST");
    let tx_hex = hex::encode(tx.to_bytes());
    opts.body(Some(&JsValue::from(tx_hex)));

    let url = &bf.url;

    let request = Request::new_with_str_and_init(&url, &opts)?;
    request.headers().set("Content-Type", "application/cbor")?;
    request.headers().set("project_id", &bf.project_id)?;

    let window = js_sys::global().unchecked_into::<globalThis>();
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;

    // `resp_value` is a `Response` object.
    assert!(resp_value.is_instance_of::<Response>());
    let resp: Response = resp_value.dyn_into().unwrap();

    // Convert this other `Promise` into a rust `Future`.
    let json = JsFuture::from(resp.json()?).await?;

    // Use serde to parse the JSON into a struct.
    let redeemer_result: RedeemerResult = json.into_serde().unwrap();

    match redeemer_result.result {
        Some(res) => {
            if let Some(e) = &res.EvaluationFailure {
                return Err(JsError::from_str(
                    &serde_json::to_string_pretty(&e).unwrap(),
                ));
            }
            let mut redeemers = Redeemers::new();
            for (pointer, eu) in &res.EvaluationResult.unwrap() {
                let r: Vec<&str> = pointer.split(":").collect();
                let tag = match r[0] {
                    "spend" => RedeemerTag::new_spend(),
                    "mint" => RedeemerTag::new_mint(),
                    "certificate" => RedeemerTag::new_cert(),
                    "withdrawal" => RedeemerTag::new_reward(),
                    _ => return Err(JsValue::NULL),
                };
                let index = &to_bignum(r[1].parse::<u64>().unwrap());
                let ex_units = ExUnits::new(&to_bignum(eu.memory), &to_bignum(eu.steps));

                for tx_redeemer in &tx.witness_set.redeemers.clone().unwrap().0 {
                    if tx_redeemer.tag() == tag && tx_redeemer.index() == *index {
                        let updated_redeemer = Redeemer::new(
                            &tx_redeemer.tag(),
                            &tx_redeemer.index(),
                            &tx_redeemer.data(),
                            &ex_units,
                        );
                        redeemers.add(&updated_redeemer);
                    }
                }
            }

            Ok(redeemers)
        }

        None => Err(JsValue::NULL),
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ScriptWitnessKind {
    NativeWitness,
    PlutusWitness,
}

#[derive(
    Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize, JsonSchema,
)]
pub enum ScriptWitnessEnum {
    NativeWitness(NativeScript),
    PlutusWitness(PlutusWitness),
}

#[wasm_bindgen]
#[derive(
    Clone, Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize, JsonSchema,
)]
pub struct PlutusWitness {
    redeemer: PlutusData,
    plutus_data: Option<PlutusData>,
    script: Option<PlutusScript>,
}

#[wasm_bindgen]
impl PlutusWitness {
    // Script is optional in Plutus v2, if script is supplied through reference input
    // Script can also be supplied separately at the end of the tx builder
    pub fn new(
        redeemer: &PlutusData,
        plutus_data: Option<PlutusData>,
        script: Option<PlutusScript>,
    ) -> Self {
        Self {
            redeemer: redeemer.clone(),
            plutus_data: plutus_data.clone(),
            script: script.clone(),
        }
    }

    pub fn plutus_data(&self) -> Option<PlutusData> {
        self.plutus_data.clone()
    }
    pub fn redeemer(&self) -> PlutusData {
        self.redeemer.clone()
    }
    pub fn script(&self) -> Option<PlutusScript> {
        self.script.clone()
    }
}

#[wasm_bindgen]
#[derive(
    Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize, JsonSchema,
)]
pub struct ScriptWitness(ScriptWitnessEnum);

to_from_json!(ScriptWitness);

#[wasm_bindgen]
impl ScriptWitness {
    pub fn new_native_witness(native_script: &NativeScript) -> Self {
        Self(ScriptWitnessEnum::NativeWitness(native_script.clone()))
    }
    pub fn new_plutus_witness(plutus_witness: &PlutusWitness) -> Self {
        Self(ScriptWitnessEnum::PlutusWitness(plutus_witness.clone()))
    }

    pub fn kind(&self) -> ScriptWitnessKind {
        match &self.0 {
            ScriptWitnessEnum::NativeWitness(_) => ScriptWitnessKind::NativeWitness,
            ScriptWitnessEnum::PlutusWitness(_) => ScriptWitnessKind::PlutusWitness,
        }
    }

    pub fn as_native_witness(&self) -> Option<NativeScript> {
        match &self.0 {
            ScriptWitnessEnum::NativeWitness(native_script) => Some(native_script.clone()),
            _ => None,
        }
    }

    pub fn as_plutus_witness(&self) -> Option<PlutusWitness> {
        match &self.0 {
            ScriptWitnessEnum::PlutusWitness(plutus_witness) => Some(plutus_witness.clone()),
            _ => None,
        }
    }
}
