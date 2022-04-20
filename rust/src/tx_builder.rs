use super::fees;
use super::output_builder::TransactionOutputAmountBuilder;
use super::utils;
use super::*;
use crate::tx_builder_utils::*;
use std::collections::{BTreeMap, BTreeSet};

// comes from witsVKeyNeeded in the Ledger spec
fn witness_keys_for_cert(
    tx_builder: &mut TransactionBuilder,
    cert_enum: &Certificate,
    script_witness: Option<ScriptWitness>,
) {
    match &cert_enum.0 {
        // stake key registrations do not require a witness
        CertificateEnum::StakeRegistration(_cert) => {}
        CertificateEnum::StakeDeregistration(cert) => match cert.stake_credential().kind() {
            StakeCredKind::Script => {
                let sw = script_witness.unwrap();
                let hash = cert.stake_credential().to_scripthash().unwrap();
                match &sw.kind() {
                    ScriptWitnessKind::NativeWitness => {
                        let native_script = sw.as_native_witness().unwrap();
                        if !tx_builder.input_types.scripts.contains(&hash) {
                            tx_builder.add_native_script(&native_script);
                            tx_builder.input_types.scripts.insert(hash.clone());
                        }
                    }
                    ScriptWitnessKind::PlutusWitness => {
                        let plutus_witness = sw.as_plutus_witness().unwrap();
                        if !tx_builder.input_types.scripts.contains(&hash)
                            && plutus_witness.script().is_some()
                        {
                            tx_builder.add_plutus_script(&plutus_witness.script().unwrap());
                            tx_builder.input_types.scripts.insert(hash.clone());
                        }
                    }
                }
            }
            StakeCredKind::Key => {
                tx_builder
                    .input_types
                    .vkeys
                    .insert(cert.stake_credential().to_keyhash().unwrap());
            }
        },
        CertificateEnum::StakeDelegation(cert) => match cert.stake_credential().kind() {
            StakeCredKind::Script => {
                let sw = script_witness.unwrap();
                let hash = cert.stake_credential().to_scripthash().unwrap();
                match &sw.kind() {
                    ScriptWitnessKind::NativeWitness => {
                        let native_script = sw.as_native_witness().unwrap();
                        if !tx_builder.input_types.scripts.contains(&hash) {
                            tx_builder.add_native_script(&native_script);
                            tx_builder.input_types.scripts.insert(hash.clone());
                        }
                    }
                    ScriptWitnessKind::PlutusWitness => {
                        let plutus_witness = sw.as_plutus_witness().unwrap();
                        if !tx_builder.input_types.scripts.contains(&hash)
                            && plutus_witness.script().is_some()
                        {
                            tx_builder.add_plutus_script(&plutus_witness.script().unwrap());
                            tx_builder.input_types.scripts.insert(hash.clone());
                        }
                    }
                }
            }
            StakeCredKind::Key => {
                tx_builder
                    .input_types
                    .vkeys
                    .insert(cert.stake_credential().to_keyhash().unwrap());
            }
        },
        CertificateEnum::PoolRegistration(cert) => {
            for owner in &cert.pool_params().pool_owners().0 {
                tx_builder.input_types.vkeys.insert(owner.clone());
            }
            tx_builder.input_types.vkeys.insert(
                Ed25519KeyHash::from_bytes(cert.pool_params().operator().to_bytes()).unwrap(),
            );
        }
        CertificateEnum::PoolRetirement(cert) => {
            tx_builder
                .input_types
                .vkeys
                .insert(Ed25519KeyHash::from_bytes(cert.pool_keyhash().to_bytes()).unwrap());
        }
        CertificateEnum::GenesisKeyDelegation(cert) => {
            tx_builder.input_types.vkeys.insert(
                Ed25519KeyHash::from_bytes(cert.genesis_delegate_hash().to_bytes()).unwrap(),
            );
        }
        // not witness as there is no single core node or genesis key that posts the certificate
        CertificateEnum::MoveInstantaneousRewardsCert(_cert) => {}
    }
}

fn fake_private_key() -> Bip32PrivateKey {
    Bip32PrivateKey::from_bytes(&[
        0xb8, 0xf2, 0xbe, 0xce, 0x9b, 0xdf, 0xe2, 0xb0, 0x28, 0x2f, 0x5b, 0xad, 0x70, 0x55, 0x62,
        0xac, 0x99, 0x6e, 0xfb, 0x6a, 0xf9, 0x6b, 0x64, 0x8f, 0x44, 0x45, 0xec, 0x44, 0xf4, 0x7a,
        0xd9, 0x5c, 0x10, 0xe3, 0xd7, 0x2f, 0x26, 0xed, 0x07, 0x54, 0x22, 0xa3, 0x6e, 0xd8, 0x58,
        0x5c, 0x74, 0x5a, 0x0e, 0x11, 0x50, 0xbc, 0xce, 0xba, 0x23, 0x57, 0xd0, 0x58, 0x63, 0x69,
        0x91, 0xf3, 0x8a, 0x37, 0x91, 0xe2, 0x48, 0xde, 0x50, 0x9c, 0x07, 0x0d, 0x81, 0x2a, 0xb2,
        0xfd, 0xa5, 0x78, 0x60, 0xac, 0x87, 0x6b, 0xc4, 0x89, 0x19, 0x2c, 0x1e, 0xf4, 0xce, 0x25,
        0x3c, 0x19, 0x7e, 0xe2, 0x19, 0xa4,
    ])
    .unwrap()
}

fn fake_raw_key_sig() -> Ed25519Signature {
    Ed25519Signature::from_bytes(vec![
        36, 248, 153, 211, 155, 23, 253, 93, 102, 193, 146, 196, 181, 13, 52, 62, 66, 247, 35, 91,
        48, 80, 76, 138, 231, 97, 159, 147, 200, 40, 220, 109, 206, 69, 104, 221, 105, 23, 124, 85,
        24, 40, 73, 45, 119, 122, 103, 39, 253, 102, 194, 251, 204, 189, 168, 194, 174, 237, 146,
        3, 44, 153, 121, 10,
    ])
    .unwrap()
}

fn fake_raw_key_public() -> PublicKey {
    PublicKey::from_bytes(&[
        207, 118, 57, 154, 33, 13, 232, 114, 14, 159, 168, 148, 228, 94, 65, 226, 154, 181, 37,
        227, 11, 196, 2, 128, 28, 7, 98, 80, 209, 88, 91, 205,
    ])
    .unwrap()
}

fn count_needed_vkeys(tx_builder: &TransactionBuilder) -> usize {
    let mut input_hashes = tx_builder.input_types.vkeys.clone();

    // required signers field
    if let Some(required_signers) = &tx_builder.required_signers {
        for key_hash in required_signers.0.iter() {
            input_hashes.insert(key_hash.clone());
        }
    }

    match &tx_builder.native_scripts {
        None => input_hashes.len(),
        Some(scripts) => {
            // Union all input keys with native script keys
            input_hashes
                .union(&RequiredSignersSet::from(scripts))
                .count()
        }
    }
}

// tx_body must be the result of building from tx_builder
// constructs the rest of the Transaction using fake witness data of the correct length
// for use in calculating the size of the final Transaction
fn fake_full_tx(
    tx_builder: &TransactionBuilder,
    body: TransactionBody,
) -> Result<Transaction, JsError> {
    let fake_key_root = fake_private_key();
    let raw_key_public = fake_raw_key_public();
    let fake_sig = fake_raw_key_sig();

    // recall: this includes keys for input, certs and withdrawals
    let vkeys = match count_needed_vkeys(tx_builder) {
        0 => None,
        x => {
            let fake_vkey_witness = Vkeywitness::new(&Vkey::new(&raw_key_public), &fake_sig);
            let mut result = Vkeywitnesses::new();
            for _i in 0..x {
                result.add(&fake_vkey_witness.clone());
            }
            Some(result)
        }
    };
    let bootstrap_keys = match tx_builder.input_types.bootstraps.len() {
        0 => None,
        _x => {
            let mut result = BootstrapWitnesses::new();
            for addr in &tx_builder.input_types.bootstraps {
                // picking icarus over daedalus for fake witness generation shouldn't matter
                result.add(&make_icarus_bootstrap_witness(
                    &TransactionHash::from([0u8; TransactionHash::BYTE_COUNT]),
                    &ByronAddress::from_bytes(addr.clone()).unwrap(),
                    &fake_key_root,
                ));
            }
            Some(result)
        }
    };

    let witness_set = TransactionWitnessSet {
        vkeys,
        native_scripts: tx_builder.native_scripts.clone(),
        bootstraps: bootstrap_keys,
        plutus_scripts: tx_builder.plutus_scripts.clone(),
        plutus_data: tx_builder.plutus_data.clone(),
        redeemers: tx_builder.redeemers.clone(),
    };
    Ok(Transaction {
        body,
        witness_set,
        is_valid: true,
        auxiliary_data: tx_builder.auxiliary_data.clone(),
    })
}

fn min_fee(tx_builder: &mut TransactionBuilder) -> Result<Coin, JsError> {
    // Commented out for performance, `min_fee` is a critical function
    // This was mostly added here as a paranoid step anyways
    // If someone is using `set_mint` and `add_mint*` API function, everything is expected to be intact
    // TODO: figure out if assert is needed here and a better way to do it maybe only once if mint doesn't change
    // if let Some(mint) = tx_builder.mint.as_ref() {
    //     assert_required_mint_scripts(mint, tx_builder.native_scripts.as_ref())?;
    // }
    let build = tx_builder.build()?;
    let full_tx = fake_full_tx(tx_builder, build)?;
    fees::min_fee(
        &full_tx,
        &tx_builder.config.fee_algo,
        &tx_builder.config.ex_unit_prices,
    )
}

// We need to know how many of each type of witness will be in the transaction so we can calculate the tx fee
#[derive(Clone, Debug)]
struct MockWitnessSet {
    vkeys: BTreeSet<Ed25519KeyHash>,
    scripts: BTreeSet<ScriptHash>,
    bootstraps: BTreeSet<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct TxBuilderInput {
    input: TransactionInput,
    amount: Value, // we need to keep track of the amount in the inputs for input selection
    redeemer: Option<Redeemer>, // we need to keep track of the redeemer index
}

#[derive(Clone, Debug)]
struct TxBuilderMint {
    policy_id: PolicyID,
    mint_assets: MintAssets,
    redeemer: Option<Redeemer>, // we need to keep track of the redeemer index
}

#[derive(Clone, Debug)]
struct TxBuilderCert {
    certificate: Certificate,
    redeemer: Option<Redeemer>, // we need to keep track of the redeemer index
}

#[derive(Clone, Debug)]
struct TxBuilderWithdrawal {
    reward_address: RewardAddress,
    coin: Coin,
    redeemer: Option<Redeemer>, // we need to keep track of the redeemer index
}

#[wasm_bindgen]
pub enum CoinSelectionStrategyCIP2 {
    /// Performs CIP2's Largest First ada-only selection. Will error if outputs contain non-ADA assets.
    LargestFirst,
    /// Performs CIP2's Random Improve ada-only selection. Will error if outputs contain non-ADA assets.
    RandomImprove,
    /// Same as LargestFirst, but before adding ADA, will insert by largest-first for each asset type.
    LargestFirstMultiAsset,
    /// Same as RandomImprove, but before adding ADA, will insert by random-improve for each asset type.
    RandomImproveMultiAsset,
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct TransactionBuilderConfig {
    fee_algo: fees::LinearFee,
    pool_deposit: BigNum,         // protocol parameter
    key_deposit: BigNum,          // protocol parameter
    max_value_size: u32,          // protocol parameter
    max_tx_size: u32,             // protocol parameter
    coins_per_utxo_word: Coin,    // protocol parameter
    ex_unit_prices: ExUnitPrices, // protocol parameter
    costmdls: Costmdls,           // protocol parameter
    blockfrost: Blockfrost,
    prefer_pure_change: bool,
    collateral_amount: BigNum,
    min_split_amount_ada: BigNum,
    prefer_split_change: bool,
    native_asset_chunk_size: u32,
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct TransactionBuilderConfigBuilder {
    fee_algo: Option<fees::LinearFee>,
    pool_deposit: Option<BigNum>,         // protocol parameter
    key_deposit: Option<BigNum>,          // protocol parameter
    max_value_size: Option<u32>,          // protocol parameter
    max_tx_size: Option<u32>,             // protocol parameter
    coins_per_utxo_word: Option<Coin>,    // protocol parameter
    ex_unit_prices: Option<ExUnitPrices>, // protocol parameter
    costmdls: Option<Costmdls>,           // protocol parameter
    blockfrost: Option<Blockfrost>,
    prefer_pure_change: bool,
    collateral_amount: BigNum,
    min_split_amount_ada: BigNum,
    prefer_split_change: bool,
    native_asset_chunk_size: Option<u32>,
}

#[wasm_bindgen]
impl TransactionBuilderConfigBuilder {
    pub fn new() -> Self {
        Self {
            fee_algo: None,
            pool_deposit: None,
            key_deposit: None,
            max_value_size: None,
            max_tx_size: None,
            coins_per_utxo_word: None,
            ex_unit_prices: None,
            costmdls: None,
            blockfrost: None,
            prefer_pure_change: false,
            collateral_amount: to_bignum(5000000),
            min_split_amount_ada: to_bignum(100),
            prefer_split_change: false,
            native_asset_chunk_size: None,
        }
    }

    pub fn fee_algo(&self, fee_algo: &fees::LinearFee) -> Self {
        let mut cfg = self.clone();
        cfg.fee_algo = Some(fee_algo.clone());
        cfg
    }

    pub fn coins_per_utxo_word(&self, coins_per_utxo_word: &Coin) -> Self {
        let mut cfg = self.clone();
        cfg.coins_per_utxo_word = Some(coins_per_utxo_word.clone());
        cfg
    }

    pub fn pool_deposit(&self, pool_deposit: &BigNum) -> Self {
        let mut cfg = self.clone();
        cfg.pool_deposit = Some(pool_deposit.clone());
        cfg
    }

    pub fn key_deposit(&self, key_deposit: &BigNum) -> Self {
        let mut cfg = self.clone();
        cfg.key_deposit = Some(key_deposit.clone());
        cfg
    }

    pub fn max_value_size(&self, max_value_size: u32) -> Self {
        let mut cfg = self.clone();
        cfg.max_value_size = Some(max_value_size);
        cfg
    }

    pub fn max_tx_size(&self, max_tx_size: u32) -> Self {
        let mut cfg = self.clone();
        cfg.max_tx_size = Some(max_tx_size);
        cfg
    }

    pub fn ex_unit_prices(&self, ex_unit_prices: &ExUnitPrices) -> Self {
        let mut cfg = self.clone();
        cfg.ex_unit_prices = Some(ex_unit_prices.clone());
        cfg
    }

    pub fn costmdls(&self, costmdls: &Costmdls) -> Self {
        let mut cfg = self.clone();
        cfg.costmdls = Some(costmdls.clone());
        cfg
    }

    pub fn blockfrost(&self, blockfrost: &Blockfrost) -> Self {
        let mut cfg = self.clone();
        cfg.blockfrost = Some(blockfrost.clone());
        cfg
    }

    pub fn prefer_pure_change(&self, prefer_pure_change: bool) -> Self {
        let mut cfg = self.clone();
        cfg.prefer_pure_change = prefer_pure_change;
        cfg
    }

    pub fn prefer_split_change(
        &self,
        prefer_split_change: bool,
        collateral_amount: BigNum,
        min_split_amount_ada: BigNum,
        native_asset_chunk_size: u32,
    ) -> Self {
        let mut cfg = self.clone();
        cfg.prefer_split_change = prefer_split_change;
        cfg.collateral_amount = collateral_amount;
        cfg.min_split_amount_ada = min_split_amount_ada;
        cfg.native_asset_chunk_size = Some(native_asset_chunk_size);
        cfg
    }

    pub fn build(&self) -> Result<TransactionBuilderConfig, JsError> {
        let cfg = self.clone();
        Ok(TransactionBuilderConfig {
            fee_algo: cfg
                .fee_algo
                .ok_or(JsError::from_str("uninitialized field: fee_algo"))?,
            pool_deposit: cfg
                .pool_deposit
                .ok_or(JsError::from_str("uninitialized field: pool_deposit"))?,
            key_deposit: cfg
                .key_deposit
                .ok_or(JsError::from_str("uninitialized field: key_deposit"))?,
            max_value_size: cfg
                .max_value_size
                .ok_or(JsError::from_str("uninitialized field: max_value_size"))?,
            max_tx_size: cfg
                .max_tx_size
                .ok_or(JsError::from_str("uninitialized field: max_tx_size"))?,
            coins_per_utxo_word: cfg.coins_per_utxo_word.ok_or(JsError::from_str(
                "uninitialized field: coins_per_utxo_word",
            ))?,
            ex_unit_prices: cfg
                .ex_unit_prices
                .ok_or(JsError::from_str("uninitialized field: ex_unit_prices"))?,
            costmdls: if cfg.costmdls.is_some() {
                cfg.costmdls.unwrap()
            } else {
                Costmdls::new()
            },
            blockfrost: if cfg.blockfrost.is_some() {
                cfg.blockfrost.unwrap()
            } else {
                Blockfrost::new("".to_string(), "".to_string())
            },
            prefer_pure_change: cfg.prefer_pure_change,
            prefer_split_change: cfg.prefer_split_change,
            collateral_amount: cfg.collateral_amount,
            min_split_amount_ada: cfg.min_split_amount_ada,
            native_asset_chunk_size: cfg.native_asset_chunk_size,
        })
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct TransactionBuilder {
    config: TransactionBuilderConfig,
    inputs: Vec<TxBuilderInput>,
    outputs: TransactionOutputs,
    change_outputs: TransactionOutputs,
    fee: Option<Coin>,
    ttl: Option<Slot>, // absolute slot number
    certs: Option<Vec<TxBuilderCert>>,
    withdrawals: Option<Vec<TxBuilderWithdrawal>>,
    auxiliary_data: Option<AuxiliaryData>,
    validity_start_interval: Option<Slot>,
    input_types: MockWitnessSet,
    mint: Option<Vec<TxBuilderMint>>,
    native_scripts: Option<NativeScripts>,
    script_data_hash: Option<ScriptDataHash>,
    collateral: Option<TransactionInputs>,
    required_signers: Option<RequiredSigners>,
    network_id: Option<NetworkId>,
    plutus_scripts: Option<PlutusScripts>,
    plutus_data: Option<PlutusList>,
    redeemers: Option<Redeemers>,
    //Babbage
    collateral_return: Option<TransactionOutput>,
    total_collateral: Option<Coin>,
    reference_inputs: Option<TransactionInputs>,
}

#[wasm_bindgen]
impl TransactionBuilder {
    /// This automatically selects and adds inputs from {inputs} consisting of just enough to cover
    /// the outputs that have already been added.
    /// This should be called after adding all certs/outputs/etc and will be an error otherwise.
    /// Uses CIP2: https://github.com/cardano-foundation/CIPs/blob/master/CIP-0002/CIP-0002.md
    /// Adding a change output must be called after via TransactionBuilder::add_change_if_needed()
    /// This function, diverging from CIP2, takes into account fees and will attempt to add additional
    /// inputs to cover the minimum fees. This does not, however, set the txbuilder's fee.
    pub fn add_inputs_from(
        &mut self,
        inputs: &TransactionUnspentOutputs,
        strategy: CoinSelectionStrategyCIP2,
    ) -> Result<(), JsError> {
        // making sure input is not already part of the tx builder inputs
        let available_inputs = &inputs
            .0
            .clone()
            .into_iter()
            .filter(|utxo| {
                self.inputs
                    .iter()
                    .all(|tx_builder_input| utxo.input != tx_builder_input.input)
            })
            .collect::<Vec<TransactionUnspentOutput>>();

        if available_inputs.len() <= 0 {
            return Ok(());
        }

        let mut input_total = self.get_total_input()?;
        let mut output_total = self
            .get_explicit_output()?
            .checked_add(&Value::new(&self.get_deposit()?))?
            .checked_add(&Value::new(&self.min_fee()?))?;
        match strategy {
            CoinSelectionStrategyCIP2::LargestFirst => {
                if self
                    .outputs
                    .0
                    .iter()
                    .any(|output| output.amount.multiasset.is_some())
                {
                    return Err(JsError::from_str("Multiasset values not supported by LargestFirst. Please use LargestFirstMultiAsset"));
                }
                self.cip2_largest_first_by(
                    available_inputs,
                    &mut (0..available_inputs.len()).collect(),
                    &mut input_total,
                    &mut output_total,
                    |value| Some(value.coin),
                )?;
            }
            CoinSelectionStrategyCIP2::RandomImprove => {
                if self
                    .outputs
                    .0
                    .iter()
                    .any(|output| output.amount.multiasset.is_some())
                {
                    return Err(JsError::from_str("Multiasset values not supported by RandomImprove. Please use RandomImproveMultiAsset"));
                }
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let mut available_indices =
                    (0..available_inputs.len()).collect::<BTreeSet<usize>>();
                self.cip2_random_improve_by(
                    available_inputs,
                    &mut available_indices,
                    &mut input_total,
                    &mut output_total,
                    |value| Some(value.coin),
                    &mut rng,
                )?;
                // Phase 3: add extra inputs needed for fees (not covered by CIP-2)
                // We do this at the end because this new inputs won't be associated with
                // a specific output, so the improvement algorithm we do above does not apply here.
                while input_total.coin < output_total.coin {
                    if available_indices.is_empty() {
                        return Err(JsError::from_str("UTxO Balance Insufficient[x]"));
                    }
                    let i = *available_indices
                        .iter()
                        .nth(rng.gen_range(0..available_indices.len()))
                        .unwrap();
                    available_indices.remove(&i);
                    let input = &available_inputs[i];
                    let input_fee = self.fee_for_input(
                        &input.output.address,
                        &input.input,
                        &input.output.amount,
                    )?;
                    self.add_input(
                        &input.output.address,
                        &input.input,
                        &input.output.amount,
                        None,
                    );
                    input_total = input_total.checked_add(&input.output.amount)?;
                    output_total = output_total.checked_add(&Value::new(&input_fee))?;
                }
            }
            CoinSelectionStrategyCIP2::LargestFirstMultiAsset => {
                // indices into {available_inputs} for inputs that contain {policy_id}:{asset_name}
                let mut available_indices = (0..available_inputs.len()).collect::<Vec<usize>>();
                // run largest-fist by each asset type
                if let Some(ma) = output_total.multiasset.clone() {
                    for (policy_id, assets) in ma.0.iter() {
                        for (asset_name, _) in assets.0.iter() {
                            self.cip2_largest_first_by(
                                available_inputs,
                                &mut available_indices,
                                &mut input_total,
                                &mut output_total,
                                |value| value.multiasset.as_ref()?.get(policy_id)?.get(asset_name),
                            )?;
                        }
                    }
                }
                // add in remaining ADA
                self.cip2_largest_first_by(
                    available_inputs,
                    &mut available_indices,
                    &mut input_total,
                    &mut output_total,
                    |value| Some(value.coin),
                )?;
            }
            CoinSelectionStrategyCIP2::RandomImproveMultiAsset => {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let mut available_indices =
                    (0..available_inputs.len()).collect::<BTreeSet<usize>>();
                // run random-improve by each asset type
                if let Some(ma) = output_total.multiasset.clone() {
                    for (policy_id, assets) in ma.0.iter() {
                        for (asset_name, _) in assets.0.iter() {
                            self.cip2_random_improve_by(
                                available_inputs,
                                &mut available_indices,
                                &mut input_total,
                                &mut output_total,
                                |value| value.multiasset.as_ref()?.get(policy_id)?.get(asset_name),
                                &mut rng,
                            )?;
                        }
                    }
                }
                // add in remaining ADA
                self.cip2_random_improve_by(
                    available_inputs,
                    &mut available_indices,
                    &mut input_total,
                    &mut output_total,
                    |value| Some(value.coin),
                    &mut rng,
                )?;
                // Phase 3: add extra inputs needed for fees (not covered by CIP-2)
                // We do this at the end because this new inputs won't be associated with
                // a specific output, so the improvement algorithm we do above does not apply here.
                while input_total.coin < output_total.coin {
                    if available_indices.is_empty() {
                        return Err(JsError::from_str("UTxO Balance Insufficient[x]"));
                    }
                    let i = *available_indices
                        .iter()
                        .nth(rng.gen_range(0..available_indices.len()))
                        .unwrap();
                    available_indices.remove(&i);
                    let input = &available_inputs[i];
                    let input_fee = self.fee_for_input(
                        &input.output.address,
                        &input.input,
                        &input.output.amount,
                    )?;
                    self.add_input(
                        &input.output.address,
                        &input.input,
                        &input.output.amount,
                        None,
                    );
                    input_total = input_total.checked_add(&input.output.amount)?;
                    output_total = output_total.checked_add(&Value::new(&input_fee))?;
                }
            }
        }

        Ok(())
    }

    fn cip2_largest_first_by<F>(
        &mut self,
        available_inputs: &Vec<TransactionUnspentOutput>,
        available_indices: &mut Vec<usize>,
        input_total: &mut Value,
        output_total: &mut Value,
        by: F,
    ) -> Result<(), JsError>
    where
        F: Fn(&Value) -> Option<BigNum>,
    {
        let mut relevant_indices = available_indices.clone();
        relevant_indices.retain(|i| by(&available_inputs[*i].output.amount).is_some());
        // ordered in ascending order by predicate {by}
        relevant_indices
            .sort_by_key(|i| by(&available_inputs[*i].output.amount).expect("filtered above"));

        // iterate in decreasing order for predicate {by}
        for i in relevant_indices.iter().rev() {
            if by(input_total).unwrap_or(BigNum::zero())
                >= by(output_total).expect("do not call on asset types that aren't in the output")
            {
                break;
            }
            let input = &available_inputs[*i];
            // differing from CIP2, we include the needed fees in the targets instead of just output values
            let input_fee =
                self.fee_for_input(&input.output.address, &input.input, &input.output.amount)?;
            self.add_input(
                &input.output.address,
                &input.input,
                &input.output.amount,
                None,
            );
            *input_total = input_total.checked_add(&input.output.amount)?;
            *output_total = output_total.checked_add(&Value::new(&input_fee))?;
            available_indices.swap_remove(available_indices.iter().position(|j| i == j).unwrap());
        }

        if by(input_total).unwrap_or(BigNum::zero())
            < by(output_total).expect("do not call on asset types that aren't in the output")
        {
            return Err(JsError::from_str("UTxO Balance Insufficient"));
        }

        Ok(())
    }

    fn cip2_random_improve_by<F>(
        &mut self,
        available_inputs: &Vec<TransactionUnspentOutput>,
        available_indices: &mut BTreeSet<usize>,
        input_total: &mut Value,
        output_total: &mut Value,
        by: F,
        rng: &mut rand::rngs::ThreadRng,
    ) -> Result<(), JsError>
    where
        F: Fn(&Value) -> Option<BigNum>,
    {
        use rand::Rng;
        // Phase 1: Random Selection
        let mut relevant_indices = available_indices
            .iter()
            .filter(|i| by(&available_inputs[**i].output.amount).is_some())
            .cloned()
            .collect::<Vec<usize>>();
        let mut associated_indices: BTreeMap<TransactionOutput, Vec<usize>> = BTreeMap::new();
        let mut outputs = self
            .outputs
            .0
            .iter()
            .filter(|output| by(&output.amount).is_some())
            .cloned()
            .collect::<Vec<TransactionOutput>>();
        outputs.sort_by_key(|output| by(&output.amount).expect("filtered above"));
        for output in outputs.iter().rev() {
            // TODO: how should we adapt this to inputs being associated when running for other assets?
            // if we do these two phases for each asset and don't take into account the other runs for other assets
            // then we over-add (and potentially fail if we don't have plenty of inputs)
            // On the other hand, the improvement phase it difficult to determine if a change is an improvement
            // if we're trying to improve for multiple assets at a time without knowing how important each input is
            // e.g. maybe we have lots of asset A but not much of B
            // For now I will just have this be entirely separarte per-asset but we might want to in a later commit
            // consider the improvements separately and have it take some kind of dot product / distance for assets
            // during the improvement phase and have the improvement phase target multiple asset types at once.
            // One issue with that is how to scale in between differnet assets. We could maybe normalize them by
            // dividing each asset type by the sum of the required asset type in all outputs.
            // Another possibility for adapting this to multiasstes is when associating an input x for asset type a
            // we try and subtract all other assets b != a from the outputs we're trying to cover.
            // It might make sense to diverge further and not consider it per-output and to instead just match against
            // the sum of all outputs as one single value.
            let mut added = BigNum::zero();
            let needed = by(&output.amount).unwrap();
            while added < needed {
                if relevant_indices.is_empty() {
                    return Err(JsError::from_str("UTxO Balance Insufficient"));
                }
                let random_index = rng.gen_range(0..relevant_indices.len());
                let i = relevant_indices.swap_remove(random_index);
                available_indices.remove(&i);
                let input = &available_inputs[i];
                added = added.checked_add(
                    &by(&input.output.amount)
                        .expect("do not call on asset types that aren't in the output"),
                )?;
                associated_indices
                    .entry(output.clone())
                    .or_default()
                    .push(i);
            }
        }
        if !relevant_indices.is_empty() {
            // Phase 2: Improvement
            for output in outputs.iter_mut() {
                let associated = associated_indices.get_mut(output).unwrap();
                for i in associated.iter_mut() {
                    let random_index = rng.gen_range(0..relevant_indices.len());
                    let j: &mut usize = relevant_indices.get_mut(random_index).unwrap();
                    let input = &available_inputs[*i];
                    let new_input = &available_inputs[*j];
                    let cur = from_bignum(&input.output.amount.coin);
                    let new = from_bignum(&new_input.output.amount.coin);
                    let min = from_bignum(&output.amount.coin);
                    let ideal = 2 * min;
                    let max = 3 * min;
                    let move_closer =
                        (ideal as i128 - new as i128).abs() < (ideal as i128 - cur as i128).abs();
                    let not_exceed_max = new < max;
                    if move_closer && not_exceed_max {
                        std::mem::swap(i, j);
                        available_indices.insert(*i);
                        available_indices.remove(j);
                    }
                }
            }
        }

        // after finalizing the improvement we need to actually add these results to the builder
        for output in outputs.iter() {
            for i in associated_indices.get(output).unwrap().iter() {
                let input = &available_inputs[*i];
                let input_fee =
                    self.fee_for_input(&input.output.address, &input.input, &input.output.amount)?;
                self.add_input(
                    &input.output.address,
                    &input.input,
                    &input.output.amount,
                    None,
                );
                *input_total = input_total.checked_add(&input.output.amount)?;
                *output_total = output_total.checked_add(&Value::new(&input_fee))?;
            }
        }

        Ok(())
    }

    /// We have to know what kind of inputs these are to know what kind of mock witnesses to create since
    /// 1) mock witnesses have different lengths depending on the type which changes the expecting fee
    /// 2) Witnesses are a set so we need to get rid of duplicates to avoid over-estimating the fee
    pub fn add_key_input(
        &mut self,
        hash: &Ed25519KeyHash,
        input: &TransactionInput,
        amount: &Value,
    ) {
        self.inputs.push(TxBuilderInput {
            input: input.clone(),
            amount: amount.clone(),
            redeemer: None,
        });
        self.input_types.vkeys.insert(hash.clone());
    }
    pub fn add_script_input(
        &mut self,
        hash: &ScriptHash,
        input: &TransactionInput,
        amount: &Value,
        script_witness: &ScriptWitness,
    ) {
        if self
            .inputs
            .iter()
            .any(|tx_builder_input| *input == tx_builder_input.input)
        {
            return;
        }

        match &script_witness.kind() {
            ScriptWitnessKind::NativeWitness => {
                let native_script = script_witness.as_native_witness().unwrap();
                if !self.input_types.scripts.contains(hash) {
                    self.add_native_script(&native_script);
                    self.input_types.scripts.insert(hash.clone());
                }

                self.inputs.push(TxBuilderInput {
                    input: input.clone(),
                    amount: amount.clone(),
                    redeemer: None,
                });
            }
            ScriptWitnessKind::PlutusWitness => {
                let plutus_witness = script_witness.as_plutus_witness().unwrap();
                if !self.input_types.scripts.contains(hash) && plutus_witness.script().is_some() {
                    self.add_plutus_script(&plutus_witness.script().unwrap());
                    self.input_types.scripts.insert(hash.clone());
                }
                self.add_plutus_data(&plutus_witness.plutus_data().clone().unwrap());

                self.inputs.push(TxBuilderInput {
                    input: input.clone(),
                    amount: amount.clone(),
                    redeemer: Some(Redeemer::new(
                        &RedeemerTag::new_spend(),
                        &to_bignum(0), // will point to correct input when finalizing txBuilder
                        &plutus_witness.redeemer(),
                        &ExUnits::new(&to_bignum(0), &to_bignum(0)), // correct ex units calculated at the end
                    )),
                });
            }
        }
    }
    pub fn add_bootstrap_input(
        &mut self,
        hash: &ByronAddress,
        input: &TransactionInput,
        amount: &Value,
    ) {
        if self
            .inputs
            .iter()
            .any(|tx_builder_input| *input == tx_builder_input.input)
        {
            return;
        }

        self.inputs.push(TxBuilderInput {
            input: input.clone(),
            amount: amount.clone(),
            redeemer: None,
        });
        self.input_types.bootstraps.insert(hash.to_bytes());
    }

    pub fn add_input(
        &mut self,
        address: &Address,
        input: &TransactionInput,
        amount: &Value,
        script_witness: Option<ScriptWitness>,
    ) {
        if self
            .inputs
            .iter()
            .any(|tx_builder_input| *input == tx_builder_input.input)
        {
            return;
        }

        match &BaseAddress::from_address(address) {
            Some(addr) => {
                match &addr.payment_cred().to_keyhash() {
                    Some(hash) => return self.add_key_input(hash, input, amount),
                    None => (),
                }
                match &addr.payment_cred().to_scripthash() {
                    Some(hash) => {
                        return self.add_script_input(hash, input, amount, &script_witness.unwrap())
                    }
                    None => (),
                }
            }
            None => (),
        }
        match &EnterpriseAddress::from_address(address) {
            Some(addr) => {
                match &addr.payment_cred().to_keyhash() {
                    Some(hash) => return self.add_key_input(hash, input, amount),
                    None => (),
                }
                match &addr.payment_cred().to_scripthash() {
                    Some(hash) => {
                        return self.add_script_input(hash, input, amount, &script_witness.unwrap())
                    }
                    None => (),
                }
            }
            None => (),
        }
        match &PointerAddress::from_address(address) {
            Some(addr) => {
                match &addr.payment_cred().to_keyhash() {
                    Some(hash) => return self.add_key_input(hash, input, amount),
                    None => (),
                }
                match &addr.payment_cred().to_scripthash() {
                    Some(hash) => {
                        return self.add_script_input(hash, input, amount, &script_witness.unwrap())
                    }
                    None => (),
                }
            }
            None => (),
        }
        match &ByronAddress::from_address(address) {
            Some(addr) => {
                return self.add_bootstrap_input(addr, input, amount);
            }
            None => (),
        }
    }

    pub fn add_reference_input(&mut self, reference_input: &TransactionInput) {
        if self.reference_inputs.is_none() {
            let inputs = TransactionInputs::new();
            self.reference_inputs = Some(inputs);
        }
        let mut inputs = self.reference_inputs.clone().unwrap();
        inputs.add(reference_input);
        self.reference_inputs = Some(inputs);
    }

    /// calculates how much the fee would increase if you added a given output
    pub fn fee_for_input(
        &self,
        address: &Address,
        input: &TransactionInput,
        amount: &Value,
    ) -> Result<Coin, JsError> {
        let mut self_copy = self.clone();

        // we need some value for these for it to be a a valid transaction
        // but since we're only calculating the difference between the fee of two transactions
        // it doesn't matter what these are set as, since it cancels out
        self_copy.set_fee(&to_bignum(0));

        let fee_before = min_fee(&mut self_copy)?;

        self_copy.add_input(&address, &input, &amount, None);
        let fee_after = min_fee(&mut self_copy)?;
        fee_after.checked_sub(&fee_before)
    }

    /// Add explicit output via a TransactionOutput object
    pub fn add_output(&mut self, output: &TransactionOutput) -> Result<(), JsError> {
        let mut_output = &mut output.clone();
        let min_ada = min_ada_required(
            &mut_output.amount(),
            mut_output.datum.is_some(),
            &self.config.coins_per_utxo_word,
        )?;
        if mut_output.amount().coin() < min_ada {
            mut_output.amount.coin = min_ada;
            // return Err(JsError::from_str(&format!(
            //     "Value {} less than the minimum UTXO value {}",
            //     from_bignum(&output.amount().coin()),
            //     from_bignum(&min_ada)
            // )));
        }
        let value_size = mut_output.amount.to_bytes().len();
        if value_size > self.config.max_value_size as usize {
            Err(JsError::from_str(&format!(
                "Maximum value size of {} exceeded. Found: {}",
                self.config.max_value_size, value_size
            )))
        } else {
            self.outputs.add(mut_output);
            Ok(())
        }
    }

    /// Add explicit change output via a TransactionOutput object
    fn add_change_output(&mut self, output: &TransactionOutput) -> Result<(), JsError> {
        let value_size = output.amount.to_bytes().len();
        if value_size > self.config.max_value_size as usize {
            return Err(JsError::from_str(&format!(
                "Maximum value size of {} exceeded. Found: {}",
                self.config.max_value_size, value_size
            )));
        }
        let min_ada = min_ada_required(
            &output.amount(),
            output.datum.is_some(),
            &self.config.coins_per_utxo_word,
        )?;
        if output.amount().coin() < min_ada {
            Err(JsError::from_str(&format!(
                "Value {} less than the minimum UTXO value {}",
                from_bignum(&output.amount().coin()),
                from_bignum(&min_ada)
            )))
        } else {
            self.change_outputs.add(output);
            Ok(())
        }
    }

    /// Add plutus scripts via a PlutusScripts object
    pub fn add_plutus_script(&mut self, plutus_script: &PlutusScript) {
        if self.plutus_scripts.is_none() {
            let scripts = PlutusScripts::new();
            self.plutus_scripts = Some(scripts);
        }
        let mut scripts = self.plutus_scripts.clone().unwrap();
        scripts.add(&plutus_script);
        self.plutus_scripts = Some(scripts);
    }

    /// Add plutus data via a PlutusData object
    pub fn add_plutus_data(&mut self, plutus_data: &PlutusData) {
        if self.plutus_data.is_none() {
            let data = PlutusList::new();
            self.plutus_data = Some(data);
        }
        let mut data = self.plutus_data.clone().unwrap();
        data.add(plutus_data);
        self.plutus_data = Some(data);
    }

    /// Add native scripts via a NativeScripts object
    pub fn add_native_script(&mut self, native_script: &NativeScript) {
        if self.native_scripts.is_none() {
            let scripts = NativeScripts::new();
            self.native_scripts = Some(scripts);
        }
        let mut scripts = self.native_scripts.clone().unwrap();
        scripts.add(native_script);
        self.native_scripts = Some(scripts);
    }

    /// Add certificate via a Certificates object
    pub fn add_certificate(
        &mut self,
        certificate: &Certificate,
        script_witness: Option<ScriptWitness>,
    ) {
        let redeemer = match &script_witness {
            Some(sw) => match sw.kind() {
                ScriptWitnessKind::NativeWitness => None,
                ScriptWitnessKind::PlutusWitness => {
                    let plutus_witness = sw.as_plutus_witness().unwrap();
                    Some(Redeemer::new(
                        &RedeemerTag::new_cert(),
                        &to_bignum(0), // will point to correct input when finalizing txBuilder
                        &plutus_witness.redeemer(),
                        &ExUnits::new(&to_bignum(0), &to_bignum(0)), // correct ex units calculated at the end
                    ))
                }
            },
            None => None,
        };

        let mut cert_array = self.certs.clone().unwrap_or(Vec::new());

        cert_array.push(TxBuilderCert {
            certificate: certificate.clone(),
            redeemer: redeemer,
        });
        self.certs = Some(cert_array.clone());

        witness_keys_for_cert(self, certificate, script_witness);
    }

    /// calculates how much the fee would increase if you added a given output
    pub fn fee_for_output(&self, output: &TransactionOutput) -> Result<Coin, JsError> {
        let mut self_copy = self.clone();

        // we need some value for these for it to be a a valid transaction
        // but since we're only calculating the different between the fee of two transactions
        // it doesn't matter what these are set as, since it cancels out
        self_copy.set_fee(&to_bignum(0));

        let fee_before = min_fee(&mut self_copy)?;

        self_copy.add_output(&output)?;
        let fee_after = min_fee(&mut self_copy)?;
        fee_after.checked_sub(&fee_before)
    }

    fn set_fee(&mut self, fee: &Coin) {
        self.fee = Some(fee.clone())
    }

    pub fn set_ttl(&mut self, ttl: &Slot) {
        self.ttl = Some(ttl.clone())
    }

    pub fn set_validity_start_interval(&mut self, validity_start_interval: &Slot) {
        self.validity_start_interval = Some(validity_start_interval.clone())
    }

    pub fn add_withdrawal(
        &mut self,
        reward_address: &RewardAddress,
        coin: &Coin,
        script_witness: Option<ScriptWitness>,
    ) {
        let redeemer = match reward_address.payment_cred().kind() {
            StakeCredKind::Key => {
                let key = reward_address.payment_cred().to_keyhash().unwrap().clone();
                self.input_types.vkeys.insert(key);
                None
            }
            StakeCredKind::Script => {
                let hash = reward_address
                    .payment_cred()
                    .to_scripthash()
                    .unwrap()
                    .clone();
                let sw = script_witness.unwrap();
                match sw.kind() {
                    ScriptWitnessKind::NativeWitness => {
                        let native_script = sw.as_native_witness().unwrap();
                        if !self.input_types.scripts.contains(&hash) {
                            self.add_native_script(&native_script);
                            self.input_types.scripts.insert(hash.clone());
                        }
                        None
                    }
                    ScriptWitnessKind::PlutusWitness => {
                        let plutus_witness = sw.as_plutus_witness().unwrap();
                        if !self.input_types.scripts.contains(&hash)
                            && plutus_witness.script().is_some()
                        {
                            self.add_plutus_script(&plutus_witness.script().unwrap());
                            self.input_types.scripts.insert(hash.clone());
                        }
                        Some(Redeemer::new(
                            &RedeemerTag::new_reward(),
                            &to_bignum(0), // will point to correct input when finalizing txBuilder
                            &plutus_witness.redeemer(),
                            &ExUnits::new(&to_bignum(0), &to_bignum(0)), // correct ex units calculated at the end
                        ))
                    }
                }
            }
        };

        let mut withdrawal_array = self.withdrawals.clone().unwrap_or(Vec::new());

        withdrawal_array.push(TxBuilderWithdrawal {
            reward_address: reward_address.clone(),
            coin: coin.clone(),
            redeemer: redeemer,
        });
        self.withdrawals = Some(withdrawal_array.clone());
    }

    pub fn auxiliary_data(&self) -> Option<AuxiliaryData> {
        self.auxiliary_data.clone()
    }

    /// Set explicit auxiliary data via an AuxiliaryData object
    /// It might contain some metadata plus native or Plutus scripts
    pub fn set_auxiliary_data(&mut self, auxiliary_data: &AuxiliaryData) {
        self.auxiliary_data = Some(auxiliary_data.clone())
    }

    /// Set metadata using a GeneralTransactionMetadata object
    /// It will be set to the existing or new auxiliary data in this builder
    pub fn set_metadata(&mut self, metadata: &GeneralTransactionMetadata) {
        let mut aux = self
            .auxiliary_data
            .as_ref()
            .cloned()
            .unwrap_or(AuxiliaryData::new());
        aux.set_metadata(metadata);
        self.set_auxiliary_data(&aux);
    }

    /// Add a single metadatum using TransactionMetadatumLabel and TransactionMetadatum objects
    /// It will be securely added to existing or new metadata in this builder
    pub fn add_metadatum(&mut self, key: &TransactionMetadatumLabel, val: &TransactionMetadatum) {
        let mut metadata = self
            .auxiliary_data
            .as_ref()
            .map(|aux| aux.metadata().as_ref().cloned())
            .unwrap_or(None)
            .unwrap_or(GeneralTransactionMetadata::new());
        metadata.insert(key, val);

        self.set_metadata(&metadata);
    }

    /// Add a single JSON metadatum using a TransactionMetadatumLabel and a String
    /// It will be securely added to existing or new metadata in this builder
    pub fn add_json_metadatum(
        &mut self,
        key: &TransactionMetadatumLabel,
        val: String,
    ) -> Result<(), JsError> {
        self.add_json_metadatum_with_schema(key, val, MetadataJsonSchema::NoConversions)
    }

    /// Add a single JSON metadatum using a TransactionMetadatumLabel, a String, and a MetadataJsonSchema object
    /// It will be securely added to existing or new metadata in this builder
    pub fn add_json_metadatum_with_schema(
        &mut self,
        key: &TransactionMetadatumLabel,
        val: String,
        schema: MetadataJsonSchema,
    ) -> Result<(), JsError> {
        let metadatum = encode_json_str_to_metadatum(val, schema)?;
        self.add_metadatum(key, &metadatum);
        Ok(())
    }

    /// Returns a copy of the current mint state in the builder
    pub fn mint(&self) -> Option<Mint> {
        self.mint_array_to_mint()
    }

    pub fn certificates(&self) -> Option<Certificates> {
        self.cert_array_to_certificates()
    }

    pub fn withdrawals(&self) -> Option<Withdrawals> {
        self.withdrawals_array_to_withdrawals()
    }

    /// Returns a copy of the current witness native scripts in the builder
    pub fn native_scripts(&self) -> Option<NativeScripts> {
        self.native_scripts.clone()
    }

    /// Add a mint entry to this builder using a PolicyID and MintAssets object
    /// It will be securely added to existing or new Mint in this builder
    /// It will securely add assets to an existing PolicyID
    /// But it will replace/overwrite any existing mint assets with the same PolicyID
    /// first redeemer applied to a PolicyID is taken for all further assets added to the same PolicyID
    pub fn add_mint(
        &mut self,
        policy_id: &PolicyID,
        mint_assets: &MintAssets,
        script_witness: Option<ScriptWitness>,
    ) {
        let redeemer = match &script_witness {
            Some(sw) => match sw.kind() {
                ScriptWitnessKind::NativeWitness => {
                    let native_script = sw.as_native_witness().unwrap();
                    if !self.input_types.scripts.contains(&policy_id) {
                        self.add_native_script(&native_script);
                        self.input_types.scripts.insert(policy_id.clone());
                    }
                    None
                }
                ScriptWitnessKind::PlutusWitness => {
                    let plutus_witness = sw.as_plutus_witness().unwrap();
                    if !self.input_types.scripts.contains(&policy_id)
                        && plutus_witness.script().is_some()
                    {
                        self.add_plutus_script(&plutus_witness.script().unwrap());
                        self.input_types.scripts.insert(policy_id.clone());
                    }
                    Some(Redeemer::new(
                        &RedeemerTag::new_mint(),
                        &to_bignum(0), // will point to correct input when finalizing txBuilder
                        &plutus_witness.redeemer(),
                        &ExUnits::new(&to_bignum(0), &to_bignum(0)), // correct ex units calculated at the end
                    ))
                }
            },
            None => None,
        };

        let mut mint_array = self.mint.clone().unwrap_or(Vec::new());

        let index = mint_array
            .iter()
            .position(|m| m.policy_id == policy_id.clone());

        match index {
            Some(i) => {
                mint_array[i]
                    .mint_assets
                    .0
                    .append(&mut mint_assets.0.clone());
            }
            None => {
                mint_array.push(TxBuilderMint {
                    policy_id: policy_id.clone(),
                    mint_assets: mint_assets.clone(),
                    redeemer: redeemer,
                });
            }
        }

        self.mint = Some(mint_array);
    }

    pub fn new(cfg: &TransactionBuilderConfig) -> Self {
        Self {
            config: cfg.clone(),
            inputs: Vec::new(),
            outputs: TransactionOutputs::new(),
            change_outputs: TransactionOutputs::new(),
            fee: None,
            ttl: None,
            certs: None,
            withdrawals: None,
            auxiliary_data: None,
            input_types: MockWitnessSet {
                vkeys: BTreeSet::new(),
                scripts: BTreeSet::new(),
                bootstraps: BTreeSet::new(),
            },
            validity_start_interval: None,
            mint: None,
            native_scripts: None,
            script_data_hash: None,
            collateral: None,
            required_signers: None,
            network_id: None,
            plutus_scripts: None,
            plutus_data: None,
            redeemers: None,
            collateral_return: None,
            total_collateral: None,
            reference_inputs: None,
        }
    }

    pub fn script_data_hash(&self) -> Option<ScriptDataHash> {
        self.script_data_hash.clone()
    }

    pub fn add_collateral(&mut self, address: &Address, collateral: &TransactionInput) {
        if self.collateral.is_none() {
            self.collateral = Some(TransactionInputs::new());
        }

        let mut inputs = self.collateral.clone().unwrap();
        inputs.add(collateral);
        self.collateral = Some(inputs.clone());

        match &BaseAddress::from_address(address) {
            Some(addr) => {
                match &addr.payment_cred().to_keyhash() {
                    Some(hash) => {
                        self.input_types.vkeys.insert(hash.clone());
                    }
                    None => (),
                }
                match &addr.payment_cred().to_scripthash() {
                    Some(hash) => {
                        self.input_types.scripts.insert(hash.clone());
                    }
                    None => (),
                }
            }
            None => (),
        }
        match &EnterpriseAddress::from_address(address) {
            Some(addr) => {
                match &addr.payment_cred().to_keyhash() {
                    Some(hash) => {
                        self.input_types.vkeys.insert(hash.clone());
                    }
                    None => (),
                }
                match &addr.payment_cred().to_scripthash() {
                    Some(hash) => {
                        self.input_types.scripts.insert(hash.clone());
                    }
                    None => (),
                }
            }
            None => (),
        }
        match &PointerAddress::from_address(address) {
            Some(addr) => {
                match &addr.payment_cred().to_keyhash() {
                    Some(hash) => {
                        self.input_types.vkeys.insert(hash.clone());
                    }
                    None => (),
                }
                match &addr.payment_cred().to_scripthash() {
                    Some(hash) => {
                        self.input_types.scripts.insert(hash.clone());
                    }
                    None => (),
                }
            }
            None => (),
        }
        match &ByronAddress::from_address(address) {
            Some(addr) => {
                self.input_types.bootstraps.insert(addr.to_bytes());
            }
            None => (),
        }
    }

    pub fn collateral(&self) -> Option<TransactionInputs> {
        self.collateral.clone()
    }

    pub fn add_required_signer(&mut self, required_signer: &Ed25519KeyHash) {
        if self.required_signers.is_none() {
            self.required_signers = Some(Ed25519KeyHashes::new());
        }
        let mut required_signers = self.required_signers.clone().unwrap();
        required_signers.add(&required_signer.clone());
        self.required_signers = Some(required_signers);
    }

    pub fn required_signers(&self) -> Option<RequiredSigners> {
        self.required_signers.clone()
    }

    pub fn set_network_id(&mut self, network_id: NetworkId) {
        self.network_id = Some(network_id)
    }

    pub fn network_id(&self) -> Option<NetworkId> {
        self.network_id.clone()
    }

    pub fn redeemers(&self) -> Option<Redeemers> {
        self.collect_redeemers().clone()
    }

    /// does not include refunds or withdrawals
    pub fn get_explicit_input(&self) -> Result<Value, JsError> {
        self.inputs
            .iter()
            .try_fold(Value::zero(), |acc, ref tx_builder_input| {
                acc.checked_add(&tx_builder_input.amount)
            })
    }

    /// withdrawals and refunds
    pub fn get_implicit_input(&self) -> Result<Value, JsError> {
        internal_get_implicit_input(
            &self.withdrawals(),
            &self.certificates(),
            &self.config.pool_deposit,
            &self.config.key_deposit,
        )
    }

    fn mint_array_to_mint(&self) -> Option<Mint> {
        match &self.mint {
            Some(tx_builder_mint) => {
                let mut collected_mint = Mint::new();

                for m in tx_builder_mint.iter() {
                    collected_mint.insert(&m.policy_id, &m.mint_assets);
                }
                Some(collected_mint)
            }
            None => None,
        }
    }

    fn cert_array_to_certificates(&self) -> Option<Certificates> {
        match &self.certs {
            Some(tx_builder_certs) => {
                let mut collected_certs = Certificates::new();

                for cert in tx_builder_certs.iter() {
                    collected_certs.add(&cert.certificate);
                }
                Some(collected_certs)
            }
            None => None,
        }
    }

    fn withdrawals_array_to_withdrawals(&self) -> Option<Withdrawals> {
        match &self.withdrawals {
            Some(tx_builder_withdrawals) => {
                let mut collected_withdrawals = Withdrawals::new();

                for m in tx_builder_withdrawals.iter() {
                    collected_withdrawals.insert(&m.reward_address, &m.coin);
                }
                Some(collected_withdrawals)
            }
            None => None,
        }
    }

    /// Returns mint as tuple of (mint_value, burn_value) or two zero values
    fn get_mint_as_values(&self) -> (Value, Value) {
        let mint = self.mint_array_to_mint();
        mint.as_ref()
            .map(|m| {
                (
                    Value::new_from_assets(&m.as_positive_multiasset()),
                    Value::new_from_assets(&m.as_negative_multiasset()),
                )
            })
            .unwrap_or((Value::zero(), Value::zero()))
    }

    /// Return explicit input plus implicit input plus mint minus burn
    pub fn get_total_input(&self) -> Result<Value, JsError> {
        let (mint_value, burn_value) = self.get_mint_as_values();
        self.get_explicit_input()?
            .checked_add(&self.get_implicit_input()?)?
            .checked_add(&mint_value)?
            .checked_sub(&burn_value)
    }

    /// does not include fee
    pub fn get_explicit_output(&self) -> Result<Value, JsError> {
        self.outputs
            .0
            .iter()
            .chain(self.change_outputs.0.iter())
            .try_fold(Value::new(&to_bignum(0)), |acc, ref output| {
                acc.checked_add(&output.amount())
            })
    }

    pub fn get_deposit(&self) -> Result<Coin, JsError> {
        internal_get_deposit(
            &self.certificates(),
            &self.config.pool_deposit,
            &self.config.key_deposit,
        )
    }

    pub fn get_fee_if_set(&self) -> Option<Coin> {
        self.fee.clone()
    }

    fn get_lexical_order_inputs(&self) -> Vec<TransactionInput> {
        let mut inputs = self
            .inputs
            .iter()
            .map(
                |TxBuilderInput {
                     input,
                     amount: _,
                     redeemer: _,
                 }| input.clone(),
            )
            .collect::<Vec<TransactionInput>>();
        inputs.sort();
        inputs
    }

    fn get_lexical_order_policy_ids(&self) -> Vec<PolicyID> {
        let mut policy_ids = self
            .mint
            .as_ref()
            .unwrap_or(Vec::new().as_ref())
            .iter()
            .map(
                |TxBuilderMint {
                     policy_id,
                     mint_assets: _,
                     redeemer: _,
                 }| policy_id.clone(),
            )
            .collect::<Vec<ScriptHash>>();
        policy_ids.sort();
        policy_ids
    }

    fn get_tx_order_certificates(&self) -> Vec<Certificate> {
        let certificates = self
            .certs
            .as_ref()
            .unwrap_or(Vec::new().as_ref())
            .iter()
            .map(
                |TxBuilderCert {
                     certificate,
                     redeemer: _,
                 }| certificate.clone(),
            )
            .collect::<Vec<Certificate>>();
        certificates
    }

    fn get_lexical_order_withdrawals(&self) -> Vec<RewardAddress> {
        let mut withdrawals = self
            .withdrawals
            .as_ref()
            .unwrap_or(Vec::new().as_ref())
            .iter()
            .map(
                |TxBuilderWithdrawal {
                     reward_address,
                     coin: _,
                     redeemer: _,
                 }| reward_address.clone(),
            )
            .collect::<Vec<RewardAddress>>();
        withdrawals.sort();
        withdrawals
    }

    /// Warning: this function will mutate the /fee/ field
    /// Make sure to call this function last after setting all other tx-body properties
    /// Editing inputs, outputs, mint, etc. after change been calculated
    /// might cause a mismatch in calculated fee versus the required fee
    pub fn add_change_if_needed(&mut self, address: &Address) -> Result<bool, JsError> {
        let fee = match &self.fee {
            None => self.min_fee(),
            // generating the change output involves changing the fee
            Some(_x) => {
                return Err(JsError::from_str(
                    "Cannot calculate change if fee was explicitly specified",
                ))
            }
        }?;

        // note: can't add data_hash to change
        // because we don't know how many change outputs will need to be created
        let datum = None;
        let script_ref = None;

        let input_total = self.get_total_input()?;

        let output_total = self
            .get_explicit_output()?
            .checked_add(&Value::new(&self.get_deposit()?))?;

        use std::cmp::Ordering;
        match &input_total.partial_cmp(&output_total.checked_add(&Value::new(&fee))?) {
            Some(Ordering::Equal) => {
                // recall: min_fee assumed the fee was the maximum possible so we definitely have enough input to cover whatever fee it ends up being
                self.set_fee(&input_total.checked_sub(&output_total)?.coin());
                Ok(false)
            }
            Some(Ordering::Less) => Err(JsError::from_str("Insufficient input in transaction")),
            Some(Ordering::Greater) => {
                fn has_assets(ma: Option<MultiAsset>) -> bool {
                    ma.map(|assets| assets.len() > 0).unwrap_or(false)
                }
                let change_estimator = input_total.checked_sub(&output_total)?;
                if has_assets(change_estimator.multiasset()) {
                    fn will_adding_asset_make_output_overflow(
                        output: &TransactionOutput,
                        current_assets: &Assets,
                        asset_to_add: (PolicyID, AssetName, BigNum),
                        max_value_size: u32,
                        coins_per_utxo_word: &Coin,
                    ) -> bool {
                        let (policy, asset_name, value) = asset_to_add;
                        let mut current_assets_clone = current_assets.clone();
                        current_assets_clone.insert(&asset_name, &value);
                        let mut amount_clone = output.amount.clone();
                        let mut val = Value::new(&Coin::zero());
                        let mut ma = MultiAsset::new();

                        ma.insert(&policy, &current_assets_clone);
                        val.set_multiasset(&ma);
                        amount_clone = amount_clone.checked_add(&val).unwrap();

                        // calculate minADA for more precise max value size
                        let min_ada = min_ada_required(&val, false, coins_per_utxo_word).unwrap();
                        amount_clone.set_coin(&min_ada);

                        amount_clone.to_bytes().len() > max_value_size as usize
                    }
                    fn pack_nfts_for_change(
                        max_value_size: u32,
                        coins_per_utxo_word: &Coin,
                        change_address: &Address,
                        change_estimator: &Value,
                        datum: Option<Datum>,
                        script_ref: Option<ScriptRef>,
                    ) -> Result<Vec<MultiAsset>, JsError> {
                        // we insert the entire available ADA temporarily here since that could potentially impact the size
                        // as it could be 1, 2 3 or 4 bytes for Coin.
                        let mut change_assets: Vec<MultiAsset> = Vec::new();

                        let mut base_coin = Value::new(&change_estimator.coin());
                        base_coin.set_multiasset(&MultiAsset::new());
                        let mut output = TransactionOutput {
                            address: change_address.clone(),
                            amount: base_coin.clone(),
                            datum: datum.clone(),
                            script_ref: script_ref.clone(),
                        };
                        // If this becomes slow on large TXs we can optimize it like the following
                        // to avoid cloning + reserializing the entire output.
                        // This would probably be more relevant if we use a smarter packing algorithm
                        // which might need to compare more size differences than greedy
                        //let mut bytes_used = output.to_bytes().len();

                        // a greedy packing is done here to avoid an exponential bin-packing
                        // which in most cases likely shouldn't be the difference between
                        // having an extra change output or not unless there are gigantic
                        // differences in NFT policy sizes
                        for (policy, assets) in change_estimator.multiasset().unwrap().0.iter() {
                            // for simplicity we also don't split assets within a single policy since
                            // you would need to have a very high amoun of assets (which add 1-36 bytes each)
                            // in a single policy to make a difference. In the future if this becomes an issue
                            // we can change that here.

                            // this is the other part of the optimization but we need to take into account
                            // the difference between CBOR encoding which can change which happens in two places:
                            // a) length within assets of one policy id
                            // b) length of the entire multiasset
                            // so for simplicity we will just do it the safe, naive way unless
                            // performance becomes an issue.
                            //let extra_bytes = policy.to_bytes().len() + assets.to_bytes().len() + 2 + cbor_len_diff;
                            //if bytes_used + extra_bytes <= max_value_size as usize {
                            let mut old_amount = output.amount.clone();
                            let mut val = Value::new(&Coin::zero());
                            let mut next_nft = MultiAsset::new();

                            let asset_names = assets.keys();
                            let mut rebuilt_assets = Assets::new();
                            for n in 0..asset_names.len() {
                                let asset_name = asset_names.get(n);
                                let value = assets.get(&asset_name).unwrap();

                                if will_adding_asset_make_output_overflow(
                                    &output,
                                    &rebuilt_assets,
                                    (policy.clone(), asset_name.clone(), value),
                                    max_value_size,
                                    coins_per_utxo_word,
                                ) {
                                    // if we got here, this means we will run into a overflow error,
                                    // so we want to split into multiple outputs, for that we...

                                    // 1. insert the current assets as they are, as this won't overflow
                                    next_nft.insert(policy, &rebuilt_assets);
                                    val.set_multiasset(&next_nft);
                                    output.amount = output.amount.checked_add(&val)?;
                                    change_assets.push(output.amount.multiasset().unwrap());

                                    // 2. create a new output with the base coin value as zero
                                    base_coin = Value::new(&Coin::zero());
                                    base_coin.set_multiasset(&MultiAsset::new());
                                    output = TransactionOutput {
                                        address: change_address.clone(),
                                        amount: base_coin.clone(),
                                        datum: datum.clone(),
                                        script_ref: script_ref.clone(),
                                    };

                                    // 3. continue building the new output from the asset we stopped
                                    old_amount = output.amount.clone();
                                    val = Value::new(&Coin::zero());
                                    next_nft = MultiAsset::new();

                                    rebuilt_assets = Assets::new();
                                }

                                rebuilt_assets.insert(&asset_name, &value);
                            }

                            next_nft.insert(policy, &rebuilt_assets);
                            val.set_multiasset(&next_nft);
                            output.amount = output.amount.checked_add(&val)?;

                            // calculate minADA for more precise max value size
                            let mut amount_clone = output.amount.clone();
                            let min_ada =
                                min_ada_required(&val, false, coins_per_utxo_word).unwrap();
                            amount_clone.set_coin(&min_ada);

                            if amount_clone.to_bytes().len() > max_value_size as usize {
                                output.amount = old_amount;
                                break;
                            }
                        }
                        change_assets.push(output.amount.multiasset().unwrap());
                        Ok(change_assets)
                    }
                    let mut change_left = input_total.checked_sub(&output_total)?;
                    let mut new_fee = fee.clone();
                    // we might need multiple change outputs for cases where the change has many asset types
                    // which surpass the max UTXO size limit
                    let minimum_utxo_val =
                        min_pure_ada(&self.config.coins_per_utxo_word, datum.is_some())?;
                    while let Some(Ordering::Greater) = change_left
                        .multiasset
                        .as_ref()
                        .map_or_else(|| None, |ma| ma.partial_cmp(&MultiAsset::new()))
                    {
                        //Use pack_nfts_for_change with different params to easily split nft change.
                        let max_value_size_change = if self.config.prefer_split_change {
                            self.config.native_asset_chunk_size
                        } else {
                            self.config.max_value_size
                        };

                        let nft_changes = pack_nfts_for_change(
                            max_value_size_change,
                            &self.config.coins_per_utxo_word,
                            address,
                            &change_left,
                            datum.clone(),
                            script_ref.clone(),
                        )?;
                        if nft_changes.len() == 0 {
                            // this likely should never happen
                            return Err(JsError::from_str("NFTs too large for change output"));
                        }
                        // we only add the minimum needed (for now) to cover this output
                        let mut change_value = Value::new(&Coin::zero());
                        for nft_change in nft_changes.iter() {
                            change_value.set_multiasset(&nft_change);
                            let min_ada = min_ada_required(
                                &change_value,
                                datum.is_some(),
                                &self.config.coins_per_utxo_word,
                            )?;
                            change_value.set_coin(&min_ada);
                            let change_output = TransactionOutput {
                                address: address.clone(),
                                amount: change_value.clone(),
                                datum: datum.clone(),
                                script_ref: script_ref.clone(),
                            };
                            // increase fee
                            let fee_for_change = self.fee_for_output(&change_output)?;
                            new_fee = new_fee.checked_add(&fee_for_change)?;
                            if change_left.coin() < min_ada.checked_add(&new_fee)? {
                                return Err(JsError::from_str("Not enough ADA leftover to include non-ADA assets in a change address"));
                            }
                            change_left = change_left.checked_sub(&change_value)?;
                            self.add_change_output(&change_output)?;
                        }
                    }
                    change_left = change_left.checked_sub(&Value::new(&new_fee))?;
                    // add potentially a separate pure ADA change output
                    let left_above_minimum = change_left.coin.compare(&minimum_utxo_val) > 0;
                    // calculate the fee for two outputs for split outputs which creates at least 2 outputs
                    let fee_for_outputs = self
                        .fee_for_output(&TransactionOutput {
                            address: address.clone(),
                            amount: Value::new(&self.config.collateral_amount.clone()),
                            datum: datum.clone(),
                            script_ref: script_ref.clone(),
                        })?
                        .checked_mul(&BigNum::from_str(&"2")?)?;
                    let above_collateral_minimum = change_left.coin.compare(
                        &self
                            .config
                            .collateral_amount
                            .checked_add(&minimum_utxo_val)?
                            .checked_add(&fee_for_outputs)?,
                    ) > 0;
                    if self.config.prefer_split_change && above_collateral_minimum {
                        // Create collateral output and subtract from change left
                        change_left =
                            change_left.checked_sub(&Value::new(&self.config.collateral_amount))?;
                        let collateral_transaction = TransactionOutput {
                            address: address.clone(),
                            amount: Value::new(&self.config.collateral_amount.clone()),
                            datum: datum.clone(),
                            script_ref: script_ref.clone(),
                        };
                        self.add_change_output(&collateral_transaction)?;
                        // add on fee for collateral
                        let fee_for_change = self.fee_for_output(&collateral_transaction)?;
                        new_fee = new_fee.checked_add(&fee_for_change)?;

                        //Split the rest of the change into decreasing outputs / 2, but if 100 ada or under stop splitting based on default config
                        while change_left
                            .coin
                            .checked_div(&BigNum::from_str(&"2")?)?
                            .compare(
                                &minimum_utxo_val.checked_mul(&self.config.min_split_amount_ada)?,
                            )
                            >= 0
                        {
                            let half = change_left.coin.checked_div(&BigNum::from_str(&"2")?)?;
                            change_left = change_left.checked_sub(&Value::new(&half))?;
                            let half_output = TransactionOutput {
                                address: address.clone(),
                                amount: Value::new(&half.clone()),
                                datum: datum.clone(),
                                script_ref: script_ref.clone(),
                            };
                            self.add_change_output(&half_output)?;
                            let fee_for_change = self.fee_for_output(&half_output)?;
                            new_fee = new_fee.checked_add(&fee_for_change)?;
                        }

                        //deal with change left before exiting if statement
                        if !change_left.is_zero() {
                            change_left = change_left.checked_sub(&change_left)?;
                            let leftover_output = TransactionOutput {
                                address: address.clone(),
                                amount: change_left,
                                datum: datum.clone(),
                                script_ref: script_ref.clone(),
                            };
                            self.add_change_output(&leftover_output)?;
                            let fee_for_change = self.fee_for_output(&leftover_output)?;
                            new_fee = new_fee.checked_add(&fee_for_change)?;
                        }
                    } else if self.config.prefer_pure_change && left_above_minimum {
                        let pure_output = TransactionOutput {
                            address: address.clone(),
                            amount: change_left.clone(),
                            datum: datum.clone(),
                            script_ref: script_ref.clone(),
                        };
                        let additional_fee = self.fee_for_output(&pure_output)?;
                        let potential_pure_value =
                            change_left.checked_sub(&Value::new(&additional_fee))?;
                        let potential_pure_above_minimum =
                            potential_pure_value.coin.compare(&minimum_utxo_val) > 0;
                        if potential_pure_above_minimum {
                            new_fee = new_fee.checked_add(&additional_fee)?;
                            change_left = Value::zero();
                            self.add_change_output(&TransactionOutput {
                                address: address.clone(),
                                amount: potential_pure_value.clone(),
                                datum: datum.clone(),
                                script_ref: script_ref.clone(),
                            })?;
                        }
                    }
                    self.set_fee(&new_fee);
                    // add in the rest of the ADA
                    if !change_left.is_zero() {
                        self.change_outputs.0.last_mut().unwrap().amount = self
                            .change_outputs
                            .0
                            .last()
                            .unwrap()
                            .amount
                            .checked_add(&change_left)?;
                    }
                    Ok(true)
                } else {
                    let min_ada = min_ada_required(
                        &change_estimator,
                        datum.is_some(),
                        &self.config.coins_per_utxo_word,
                    )?;
                    // no-asset case so we have no problem burning the rest if there is no other option
                    fn burn_extra(
                        builder: &mut TransactionBuilder,
                        burn_amount: &BigNum,
                    ) -> Result<bool, JsError> {
                        // recall: min_fee assumed the fee was the maximum possible so we definitely have enough input to cover whatever fee it ends up being
                        builder.set_fee(burn_amount);
                        Ok(false) // not enough input to covert the extra fee from adding an output so we just burn whatever is left
                    }
                    match change_estimator.coin() >= min_ada {
                        false => burn_extra(self, &change_estimator.coin()),
                        true => {
                            // check how much the fee would increase if we added a change output
                            let fee_for_change = self.fee_for_output(&TransactionOutput {
                                address: address.clone(),
                                amount: change_estimator.clone(),
                                datum: datum.clone(),
                                script_ref: script_ref.clone(),
                            })?;

                            let new_fee = fee.checked_add(&fee_for_change)?;
                            match change_estimator.coin()
                                >= min_ada.checked_add(&Value::new(&new_fee).coin())?
                            {
                                false => burn_extra(self, &change_estimator.coin()),
                                true => {
                                    // recall: min_fee assumed the fee was the maximum possible so we definitely have enough input to cover whatever fee it ends up being
                                    self.set_fee(&new_fee);

                                    self.add_change_output(&TransactionOutput {
                                        address: address.clone(),
                                        amount: change_estimator
                                            .checked_sub(&Value::new(&new_fee.clone()))?,
                                        datum: datum.clone(),
                                        script_ref: script_ref.clone(),
                                    })?;

                                    Ok(true)
                                }
                            }
                        }
                    }
                }
            }
            None => Err(JsError::from_str(
                "missing input or output for some native asset",
            )),
        }
    }

    fn build_and_size(&mut self) -> Result<(TransactionBody, usize), JsError> {
        let fee = self
            .fee
            .ok_or_else(|| JsError::from_str("Fee not specified"))?;

        let mut total_outputs = self.outputs.clone();
        for change_output in &self.change_outputs.0 {
            total_outputs.add(&change_output);
        }

        let built = TransactionBody {
            inputs: TransactionInputs(
                self.inputs
                    .iter()
                    .map(|ref tx_builder_input| tx_builder_input.input.clone())
                    .collect(),
            ),
            outputs: total_outputs,
            fee: fee,
            ttl: self.ttl,
            certs: self.certificates(),
            withdrawals: self.withdrawals(),
            update: None,
            auxiliary_data_hash: match &self.auxiliary_data {
                None => None,
                Some(x) => Some(utils::hash_auxiliary_data(x)),
            },
            validity_start_interval: self.validity_start_interval,
            mint: self.mint_array_to_mint(),
            script_data_hash: match self.redeemers.is_some() || self.plutus_data.is_some() {
                false => None,
                true => Some(utils::hash_script_data(
                    &self.redeemers.clone().unwrap_or(Redeemers::new()),
                    &self.config.costmdls,
                    self.plutus_data.clone(),
                )),
            },
            collateral: self.collateral.clone(),
            required_signers: self.required_signers.clone(),
            network_id: self.network_id.clone(),
            // TODO: babbage support
            collateral_return: None,
            total_collateral: None,
            reference_inputs: self.reference_inputs.clone(),
        };
        // we must build a tx with fake data (of correct size) to check the final Transaction size
        let full_tx = fake_full_tx(self, built)?;
        let full_tx_size = full_tx.to_bytes().len();
        return Ok((full_tx.body, full_tx_size));
    }

    pub fn full_size(&mut self) -> Result<usize, JsError> {
        return self.build_and_size().map(|r| r.1);
    }

    pub fn output_sizes(&self) -> Vec<usize> {
        return self
            .outputs
            .0
            .iter()
            .chain(self.change_outputs.0.iter())
            .map(|o| o.to_bytes().len())
            .collect();
    }

    pub fn outputs(&self) -> TransactionOutputs {
        let mut total_outputs = self.outputs.clone();
        for change_output in &self.change_outputs.0 {
            total_outputs.add(&change_output);
        }
        total_outputs
    }

    /// Returns object the body of the new transaction
    /// Auxiliary data itself is not included
    /// You can use `get_auxiliary_data` or `build_tx`
    fn build(&mut self) -> Result<TransactionBody, JsError> {
        let (body, full_tx_size) = self.build_and_size()?;
        if full_tx_size > self.config.max_tx_size as usize {
            Err(JsError::from_str(&format!(
                "Maximum transaction size of {} exceeded. Found: {}",
                self.config.max_tx_size, full_tx_size
            )))
        } else {
            Ok(body)
        }
    }

    fn collect_redeemers(&self) -> Option<Redeemers> {
        let mut collected_redeemers = Redeemers::new();

        let lexical_order_inputs = self.get_lexical_order_inputs();
        for input in &self.inputs {
            if let Some(redeemer) = &input.redeemer {
                let index = to_bignum(
                    lexical_order_inputs
                        .iter()
                        .position(|i| *i == input.input)
                        .unwrap() as u64,
                );
                let new_redeemer = Redeemer::new(
                    &redeemer.tag(),
                    &index,
                    &redeemer.data(),
                    &redeemer.ex_units(),
                );
                collected_redeemers.add(&new_redeemer);
            }
        }

        let lexical_order_policy_id = self.get_lexical_order_policy_ids();
        for m in self.mint.as_ref().unwrap_or(&Vec::new()) {
            if let Some(redeemer) = &m.redeemer {
                let index = to_bignum(
                    lexical_order_policy_id
                        .iter()
                        .position(|policy_id| *policy_id == m.policy_id)
                        .unwrap() as u64,
                );
                let new_redeemer = Redeemer::new(
                    &redeemer.tag(),
                    &index,
                    &redeemer.data(),
                    &redeemer.ex_units(),
                );
                collected_redeemers.add(&new_redeemer);
            }
        }

        let tx_order_certificates = self.get_tx_order_certificates();
        for cert in self.certs.as_ref().unwrap_or(&Vec::new()) {
            if let Some(redeemer) = &cert.redeemer {
                let index = to_bignum(
                    tx_order_certificates
                        .iter()
                        .position(|c| *c == cert.certificate)
                        .unwrap() as u64,
                );
                let new_redeemer = Redeemer::new(
                    &redeemer.tag(),
                    &index,
                    &redeemer.data(),
                    &redeemer.ex_units(),
                );
                collected_redeemers.add(&new_redeemer);
            }
        }

        let lexical_order_withdrawals = self.get_lexical_order_withdrawals();
        for w in self.withdrawals.as_ref().unwrap_or(&Vec::new()) {
            if let Some(redeemer) = &w.redeemer {
                let index = to_bignum(
                    lexical_order_withdrawals
                        .iter()
                        .position(|reward_address| *reward_address == w.reward_address)
                        .unwrap() as u64,
                );
                let new_redeemer = Redeemer::new(
                    &redeemer.tag(),
                    &index,
                    &redeemer.data(),
                    &redeemer.ex_units(),
                );
                collected_redeemers.add(&new_redeemer);
            }
        }

        if collected_redeemers.len() > 0 {
            return Some(collected_redeemers);
        }
        None
    }

    /// Returns full Transaction object with the body and the auxiliary data
    /// NOTE: witness_set will contain all mint_scripts if any been added or set
    /// takes fetched ex units into consideration
    /// async call
    /// NOTE: is_valid set to true
    pub async fn construct(self) -> Result<Transaction, JsError> {
        let this = &mut self.clone();
        this.redeemers = this.collect_redeemers();
        let (body, full_tx_size) = this.build_and_size()?;
        if full_tx_size > this.config.max_tx_size as usize {
            Err(JsError::from_str(&format!(
                "Maximum transaction size of {} exceeded. Found: {}",
                this.config.max_tx_size, full_tx_size
            )))
        } else {
            let full_tx = Transaction {
                body: body.clone(),
                witness_set: this.get_witness_set(),
                is_valid: true,
                auxiliary_data: this.auxiliary_data.clone(),
            };

            if let Some(_) = &this.redeemers {
                let updated_redeemers =
                    get_ex_units(full_tx.clone(), &this.config.blockfrost).await?;
                this.redeemers = Some(updated_redeemers);

                // set new fee and and subract remaining amount from a change output
                let old_fee = full_tx.body.fee.clone();
                let new_fee = min_fee(this)?;
                this.set_fee(&new_fee);
                let amount_to_subtract = new_fee.checked_sub(&old_fee)?;
                // get index of a change output which has sufficient balance and is not collateral change output
                let mut index_or_error = this
                    .change_outputs
                    .0
                    .iter()
                    .position(|output| {
                        output
                            .amount
                            .coin
                            .checked_sub(&amount_to_subtract)
                            .unwrap_or(to_bignum(0))
                            .compare(
                                &min_ada_required(
                                    &output.amount(),
                                    output.datum.is_some(),
                                    &this.config.coins_per_utxo_word,
                                )
                                .unwrap(),
                            )
                            .is_positive()
                            && output.amount.coin.compare(&self.config.collateral_amount) != 0
                    })
                    .ok_or_else(|| JsError::from_str("No change output found"));

                // didn't find any other outputs with enough lovelaces so now check all change outputs one more time
                if index_or_error.is_err() {
                    index_or_error = this
                        .change_outputs
                        .0
                        .iter()
                        .position(|output| {
                            output
                                .amount
                                .coin
                                .checked_sub(&amount_to_subtract)
                                .unwrap_or(to_bignum(0))
                                .compare(
                                    &min_ada_required(
                                        &output.amount(),
                                        output.datum.is_some(),
                                        &this.config.coins_per_utxo_word,
                                    )
                                    .unwrap(),
                                )
                                .is_positive()
                        })
                        .ok_or_else(|| JsError::from_str("No change output found"));
                }
                let index = index_or_error.unwrap();

                this.change_outputs.0[index].amount = this.change_outputs.0[index]
                    .amount
                    .checked_sub(&Value::new(&amount_to_subtract))?;

                let (final_body, final_full_tx_size) = this.build_and_size()?;

                if final_full_tx_size > this.config.max_tx_size as usize {
                    return Err(JsError::from_str(&format!(
                        "Maximum transaction size of {} exceeded. Found: {}",
                        this.config.max_tx_size, final_full_tx_size
                    )));
                }

                let final_tx = &mut Transaction {
                    body: final_body.clone(),
                    witness_set: this.get_witness_set(),
                    is_valid: true,
                    auxiliary_data: this.auxiliary_data.clone(),
                };

                return Ok(final_tx.clone());
            }

            Ok(full_tx)
        }
    }

    // This function should be producing the total witness-set
    // that is created by the tx-builder itself,
    // before the transaction is getting signed by the actual wallet.
    // E.g. scripts or something else that has been used during the tx preparation
    fn get_witness_set(&self) -> TransactionWitnessSet {
        let mut wit = TransactionWitnessSet::new();
        if let Some(scripts) = self.native_scripts.as_ref() {
            wit.set_native_scripts(scripts);
        }
        if let Some(scripts) = self.plutus_scripts.as_ref() {
            wit.set_plutus_scripts(scripts);
        }
        if let Some(data) = self.plutus_data.as_ref() {
            wit.set_plutus_data(data);
        }
        if let Some(redeemers) = self.redeemers.as_ref() {
            wit.set_redeemers(redeemers);
        }
        wit
    }

    /// Returns full Transaction object with the body and the auxiliary data
    /// NOTE: witness_set will contain all mint_scripts if any been added or set
    /// NOTE: is_valid set to true
    pub fn build_tx(&mut self) -> Result<Transaction, JsError> {
        self.redeemers = self.collect_redeemers();
        Ok(Transaction {
            body: self.build()?,
            witness_set: self.get_witness_set(),
            is_valid: true,
            auxiliary_data: self.auxiliary_data.clone(),
        })
    }

    /// warning: sum of all parts of a transaction must equal 0. You cannot just set the fee to the min value and forget about it
    /// warning: min_fee may be slightly larger than the actual minimum fee (ex: a few lovelaces)
    /// this is done to simplify the library code, but can be fixed later
    pub fn min_fee(&self) -> Result<Coin, JsError> {
        let mut self_copy = self.clone();
        self_copy.set_fee(&to_bignum(0x1_00_00_00_00));
        min_fee(&mut self_copy)
    }
}

#[cfg(test)]
mod tests {

    use super::output_builder::TransactionOutputBuilder;
    use super::*;
    use fees::*;
    use itertools::Itertools;

    const MAX_VALUE_SIZE: u32 = 4000;
    const MAX_TX_SIZE: u32 = 8000; // might be out of date but suffices for our tests
                                   // this is what is used in mainnet
    static COINS_PER_UTXO_WORD: u64 = 34_482;

    fn genesis_id() -> TransactionHash {
        TransactionHash::from([0u8; TransactionHash::BYTE_COUNT])
    }

    fn root_key_15() -> Bip32PrivateKey {
        // art forum devote street sure rather head chuckle guard poverty release quote oak craft enemy
        let entropy = [
            0x0c, 0xcb, 0x74, 0xf3, 0x6b, 0x7d, 0xa1, 0x64, 0x9a, 0x81, 0x44, 0x67, 0x55, 0x22,
            0xd4, 0xd8, 0x09, 0x7c, 0x64, 0x12,
        ];
        Bip32PrivateKey::from_bip39_entropy(&entropy, &[])
    }

    fn fake_key_hash(x: u8) -> Ed25519KeyHash {
        Ed25519KeyHash::from_bytes(vec![
            x, 239, 181, 120, 142, 135, 19, 200, 68, 223, 211, 43, 46, 145, 222, 30, 48, 159, 239,
            255, 213, 85, 248, 39, 204, 158, 225, 100,
        ])
        .unwrap()
    }

    fn harden(index: u32) -> u32 {
        index | 0x80_00_00_00
    }

    #[test]
    fn check_fake_private_key() {
        let fpk = fake_private_key();
        assert_eq!(
            fpk.to_bech32(),
            "xprv1hretan5mml3tq2p0twkhq4tz4jvka7m2l94kfr6yghkyfar6m9wppc7h9unw6p65y23kakzct3695rs32z7vaw3r2lg9scmfj8ec5du3ufydu5yuquxcz24jlkjhsc9vsa4ufzge9s00fn398svhacse5su2awrw",
        );
        assert_eq!(
            fpk.to_public().to_bech32(),
            "xpub1eamrnx3pph58yr5l4z2wghjpu2dt2f0rp0zq9qquqa39p52ct0xercjgmegfcpcdsy4t9ld90ps2epmtcjy3jtq77n8z20qe0m3pnfqntgrgj",
        );
    }

    fn byron_address() -> Address {
        ByronAddress::from_base58("Ae2tdPwUPEZ5uzkzh1o2DHECiUi3iugvnnKHRisPgRRP3CTF4KCMvy54Xd3")
            .unwrap()
            .to_address()
    }

    fn create_linear_fee(coefficient: u64, constant: u64) -> LinearFee {
        LinearFee::new(&to_bignum(coefficient), &to_bignum(constant))
    }

    fn create_default_linear_fee() -> LinearFee {
        create_linear_fee(500, 2)
    }

    fn create_tx_builder_full(
        linear_fee: &LinearFee,
        pool_deposit: u64,
        key_deposit: u64,
        max_val_size: u32,
        coins_per_utxo_word: u64,
    ) -> TransactionBuilder {
        let cfg = TransactionBuilderConfigBuilder::new()
            .fee_algo(linear_fee)
            .pool_deposit(&to_bignum(pool_deposit))
            .key_deposit(&to_bignum(key_deposit))
            .max_value_size(max_val_size)
            .max_tx_size(MAX_TX_SIZE)
            .coins_per_utxo_word(&to_bignum(coins_per_utxo_word))
            .ex_unit_prices(&ExUnitPrices::from_float(0.0, 0.0))
            .build()
            .unwrap();
        TransactionBuilder::new(&cfg)
    }

    fn create_tx_builder(
        linear_fee: &LinearFee,
        coins_per_utxo_word: u64,
        pool_deposit: u64,
        key_deposit: u64,
    ) -> TransactionBuilder {
        create_tx_builder_full(
            linear_fee,
            pool_deposit,
            key_deposit,
            MAX_VALUE_SIZE,
            coins_per_utxo_word,
        )
    }

    fn create_reallistic_tx_builder() -> TransactionBuilder {
        create_tx_builder(
            &create_linear_fee(44, 155381),
            COINS_PER_UTXO_WORD,
            500000000,
            2000000,
        )
    }

    fn create_tx_builder_with_fee_and_val_size(
        linear_fee: &LinearFee,
        max_val_size: u32,
    ) -> TransactionBuilder {
        create_tx_builder_full(linear_fee, 1, 1, max_val_size, 1)
    }

    fn create_tx_builder_with_fee(linear_fee: &LinearFee) -> TransactionBuilder {
        create_tx_builder(linear_fee, 1, 1, 1)
    }

    fn create_tx_builder_with_fee_and_pure_change(linear_fee: &LinearFee) -> TransactionBuilder {
        TransactionBuilder::new(
            &TransactionBuilderConfigBuilder::new()
                .fee_algo(linear_fee)
                .pool_deposit(&to_bignum(1))
                .key_deposit(&to_bignum(1))
                .max_value_size(MAX_VALUE_SIZE)
                .max_tx_size(MAX_TX_SIZE)
                .coins_per_utxo_word(&to_bignum(1))
                .prefer_pure_change(true)
                .ex_unit_prices(&ExUnitPrices::from_float(0.0, 0.0))
                .build()
                .unwrap(),
        )
    }

    fn create_tx_builder_with_key_deposit(deposit: u64) -> TransactionBuilder {
        create_tx_builder(&create_default_linear_fee(), 1, 1, deposit)
    }

    fn create_default_tx_builder() -> TransactionBuilder {
        create_tx_builder_with_fee(&create_default_linear_fee())
    }

    #[test]
    fn build_tx_with_change() {
        let mut tx_builder = create_default_tx_builder();
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();

        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw_key().hash());
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw_key().hash());
        let addr_net_0 = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &spend_cred,
            &stake_cred,
        )
        .to_address();
        tx_builder.add_key_input(
            &spend.to_raw_key().hash(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(1_000_000)),
        );
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&addr_net_0)
                    .next()
                    .unwrap()
                    .with_coin(&to_bignum(29))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        tx_builder.set_ttl(&1000.into());

        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw_key().hash());
        let change_addr = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &change_cred,
            &stake_cred,
        )
        .to_address();
        let added_change = tx_builder.add_change_if_needed(&change_addr);
        assert!(added_change.unwrap());
        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            2
        );
        assert_eq!(
            tx_builder
                .get_explicit_input()
                .unwrap()
                .checked_add(&tx_builder.get_implicit_input().unwrap())
                .unwrap(),
            tx_builder
                .get_explicit_output()
                .unwrap()
                .checked_add(&Value::new(&tx_builder.get_fee_if_set().unwrap()))
                .unwrap()
        );
        assert_eq!(tx_builder.full_size().unwrap(), 285);
        assert_eq!(tx_builder.output_sizes(), vec![62, 65]);
        let _final_tx = tx_builder.build(); // just test that it doesn't throw
    }

    #[test]
    fn fetch_request_to_serde() {
        let data = r#"
            {
                "type": "result",
                "version": "1.0",
                "servicename": "ogmios",
                "methodname": "evalEx",
                "result": {
                    "EvaluationResult": {
                        "spend:0": {
                            "memory": 10000000,
                            "steps": 20000000
                        }
                    }
                }
            }
        "#;

        let g: RedeemerResult = serde_json::from_str(data).unwrap();
        match g.result {
            Some(res) => {
                for (pointer, eu) in &res.EvaluationResult.unwrap() {
                    assert_eq!(pointer, &"spend:0".to_string());
                    assert_eq!(eu.memory, 10000000);
                    assert_eq!(eu.steps, 20000000);

                    let r: Vec<&str> = pointer.split(":").collect();
                    assert_eq!(r[0], "spend");
                    assert_eq!(r[1], "0");
                }
            }
            None => {
                assert!(false);
            }
        }
    }

    #[test]
    fn fetch_request_to_serde_with_failure() {
        let data = r#"
            {
                "type": "result",
                "version": "1.0",
                "servicename": "ogmios",
                "methodname": "evalEx",
                "result": {
                    "EvaluationFailure": {
                        "spend:0": {"error": "Caluldation error"}
                    }
                }
            }
        "#;

        let g: RedeemerResult = serde_json::from_str(data).unwrap();
        match g.result {
            Some(res) => {
                if let Some(e) = &res.EvaluationFailure {
                    print!("{}", &serde_json::to_string_pretty(&e).unwrap());
                } else {
                    assert!(false);
                    for (pointer, eu) in &res.EvaluationResult.unwrap() {
                        assert_eq!(pointer, &"spend:0".to_string());
                        assert_eq!(eu.memory, 10000000);
                        assert_eq!(eu.steps, 20000000);

                        let r: Vec<&str> = pointer.split(":").collect();
                        assert_eq!(r[0], "spend");
                        assert_eq!(r[1], "0");
                    }
                }
            }
            None => {
                assert!(false);
            }
        }
    }

    #[test]
    fn build_tx_without_change() {
        let mut tx_builder = create_default_tx_builder();
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();

        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw_key().hash());
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw_key().hash());
        let addr_net_0 = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &spend_cred,
            &stake_cred,
        )
        .to_address();
        tx_builder.add_key_input(
            &spend.to_raw_key().hash(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(1_000_000)),
        );
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&addr_net_0)
                    .next()
                    .unwrap()
                    .with_coin(&to_bignum(880_000))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        tx_builder.set_ttl(&1000.into());

        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw_key().hash());
        let change_addr = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &change_cred,
            &stake_cred,
        )
        .to_address();
        let added_change = tx_builder.add_change_if_needed(&change_addr);
        assert!(!added_change.unwrap());
        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            1
        );
        assert_eq!(
            tx_builder
                .get_explicit_input()
                .unwrap()
                .checked_add(&tx_builder.get_implicit_input().unwrap())
                .unwrap(),
            tx_builder
                .get_explicit_output()
                .unwrap()
                .checked_add(&Value::new(&tx_builder.get_fee_if_set().unwrap()))
                .unwrap()
        );
        let _final_tx = tx_builder.build(); // just test that it doesn't throw
    }

    #[test]
    fn build_tx_with_certs() {
        let mut tx_builder = create_tx_builder_with_key_deposit(1_000_000);
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();

        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw_key().hash());
        tx_builder.add_key_input(
            &spend.to_raw_key().hash(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(5_000_000)),
        );
        tx_builder.set_ttl(&1000.into());

        tx_builder.add_certificate(
            &Certificate::new_stake_registration(&StakeRegistration::new(&stake_cred)),
            None,
        );
        tx_builder.add_certificate(
            &Certificate::new_stake_delegation(&StakeDelegation::new(
                &stake_cred,
                &stake.to_raw_key().hash(), // in reality, this should be the pool owner's key, not ours
            )),
            None,
        );

        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw_key().hash());
        let change_addr = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &change_cred,
            &stake_cred,
        )
        .to_address();
        tx_builder.add_change_if_needed(&change_addr).unwrap();
        assert_eq!(tx_builder.min_fee().unwrap().to_str(), "214002");
        assert_eq!(tx_builder.get_fee_if_set().unwrap().to_str(), "214002");
        assert_eq!(tx_builder.get_deposit().unwrap().to_str(), "1000000");
        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            1
        );
        assert_eq!(
            tx_builder
                .get_explicit_input()
                .unwrap()
                .checked_add(&tx_builder.get_implicit_input().unwrap())
                .unwrap(),
            tx_builder
                .get_explicit_output()
                .unwrap()
                .checked_add(&Value::new(&tx_builder.get_fee_if_set().unwrap()))
                .unwrap()
                .checked_add(&Value::new(&tx_builder.get_deposit().unwrap()))
                .unwrap()
        );
        let _final_tx = tx_builder.build(); // just test that it doesn't throw
    }

    #[test]
    fn build_tx_exact_amount() {
        // transactions where sum(input) == sum(output) exact should pass
        let mut tx_builder = create_tx_builder_with_fee(&create_linear_fee(0, 0));
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();
        tx_builder.add_key_input(
            &&spend.to_raw_key().hash(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(100)),
        );
        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw_key().hash());
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw_key().hash());
        let addr_net_0 = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &spend_cred,
            &stake_cred,
        )
        .to_address();
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&addr_net_0)
                    .next()
                    .unwrap()
                    .with_coin(&to_bignum(100))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        tx_builder.set_ttl(&0.into());

        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw_key().hash());
        let change_addr = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &change_cred,
            &stake_cred,
        )
        .to_address();
        let added_change = tx_builder.add_change_if_needed(&change_addr).unwrap();
        assert_eq!(added_change, false);
        let final_tx = tx_builder.build().unwrap();
        assert_eq!(final_tx.outputs().len(), 1);
    }

    #[test]
    fn build_tx_exact_change() {
        // transactions where we have exactly enough ADA to add change should pass
        let mut tx_builder = create_tx_builder_with_fee(&create_linear_fee(0, 0));
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();
        tx_builder.add_key_input(
            &&spend.to_raw_key().hash(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(58)),
        );
        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw_key().hash());
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw_key().hash());
        let addr_net_0 = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &spend_cred,
            &stake_cred,
        )
        .to_address();
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&addr_net_0)
                    .next()
                    .unwrap()
                    .with_coin(&to_bignum(29))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        tx_builder.set_ttl(&0.into());

        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw_key().hash());
        let change_addr = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &change_cred,
            &stake_cred,
        )
        .to_address();
        let added_change = tx_builder.add_change_if_needed(&change_addr).unwrap();
        assert_eq!(added_change, true);
        let final_tx = tx_builder.build().unwrap();
        assert_eq!(final_tx.outputs().len(), 2);
        assert_eq!(final_tx.outputs().get(1).amount().coin().to_str(), "29");
    }

    #[test]
    #[should_panic]
    fn build_tx_insufficient_deposit() {
        // transactions should fail with insufficient fees if a deposit is required
        let mut tx_builder = create_tx_builder_with_key_deposit(5);
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();
        tx_builder.add_key_input(
            &&spend.to_raw_key().hash(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(5)),
        );
        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw_key().hash());
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw_key().hash());
        let addr_net_0 = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &spend_cred,
            &stake_cred,
        )
        .to_address();
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&addr_net_0)
                    .next()
                    .unwrap()
                    .with_coin(&to_bignum(5))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        tx_builder.set_ttl(&0.into());

        // add a cert which requires a deposit
        tx_builder.add_certificate(
            &Certificate::new_stake_registration(&StakeRegistration::new(&stake_cred)),
            None,
        );

        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw_key().hash());
        let change_addr = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &change_cred,
            &stake_cred,
        )
        .to_address();

        tx_builder.add_change_if_needed(&change_addr).unwrap();
    }

    #[test]
    fn build_tx_with_inputs() {
        let mut tx_builder = create_default_tx_builder();
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();

        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw_key().hash());
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw_key().hash());

        {
            assert_eq!(
                tx_builder
                    .fee_for_input(
                        &EnterpriseAddress::new(NetworkInfo::testnet().network_id(), &spend_cred)
                            .to_address(),
                        &TransactionInput::new(&genesis_id(), &0.into()),
                        &Value::new(&to_bignum(1_000_000))
                    )
                    .unwrap()
                    .to_str(),
                "69500"
            );
            tx_builder.add_input(
                &EnterpriseAddress::new(NetworkInfo::testnet().network_id(), &spend_cred)
                    .to_address(),
                &TransactionInput::new(&genesis_id(), &0.into()),
                &Value::new(&to_bignum(1_000_000)),
                None,
            );
        }
        tx_builder.add_input(
            &BaseAddress::new(
                NetworkInfo::testnet().network_id(),
                &spend_cred,
                &stake_cred,
            )
            .to_address(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(1_000_000)),
            None,
        );
        tx_builder.add_input(
            &PointerAddress::new(
                NetworkInfo::testnet().network_id(),
                &spend_cred,
                &Pointer::new(&to_bignum(0), &to_bignum(0), &to_bignum(0)),
            )
            .to_address(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(1_000_000)),
            None,
        );
        tx_builder.add_input(
            &ByronAddress::icarus_from_key(&spend, NetworkInfo::testnet().protocol_magic())
                .to_address(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(1_000_000)),
            None,
        );

        assert_eq!(tx_builder.inputs.len(), 1);
    }

    #[test]
    fn build_tx_with_mint_all_sent() {
        let mut tx_builder = create_tx_builder_with_fee(&create_linear_fee(0, 1));
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();

        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw_key().hash());
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw_key().hash());

        // Input with 150 coins
        tx_builder.add_input(
            &EnterpriseAddress::new(NetworkInfo::testnet().network_id(), &spend_cred).to_address(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(150)),
            None,
        );

        let addr_net_0 = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &spend_cred,
            &stake_cred,
        )
        .to_address();

        let (min_script, policy_id) = mint_script_and_policy(0);
        let name = AssetName::new(vec![0u8, 1, 2, 3]).unwrap();
        let amount = to_bignum(1234);

        // Adding mint of the asset - which should work as an input
        tx_builder.add_mint(
            &policy_id,
            &MintAssets::new_from_entry(&name, Int::new(&amount)),
            Some(ScriptWitness::new_native_witness(&min_script)),
        );

        let mut ass = Assets::new();
        ass.insert(&name, &amount);
        let mut mass = MultiAsset::new();
        mass.insert(&policy_id, &ass);

        // One coin and the minted asset goes into the output
        let mut output_amount = Value::new(&to_bignum(50));
        output_amount.set_multiasset(&mass);

        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&addr_net_0)
                    .next()
                    .unwrap()
                    .with_value(&output_amount)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw_key().hash());
        let change_addr = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &change_cred,
            &stake_cred,
        )
        .to_address();

        let added_change = tx_builder.add_change_if_needed(&change_addr).unwrap();
        assert!(added_change);
        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            2
        );

        // Change must be one remaining coin because fee is one constant coin
        let change = tx_builder
            .outputs
            .0
            .iter()
            .chain(tx_builder.change_outputs.0.iter())
            .collect_vec()
            .get(1)
            .unwrap()
            .amount();
        assert_eq!(change.coin(), to_bignum(99));
        assert!(change.multiasset().is_none());
    }

    #[test]
    fn build_tx_with_mint_in_change() {
        let mut tx_builder = create_tx_builder_with_fee(&create_linear_fee(0, 1));
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();

        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw_key().hash());
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw_key().hash());

        // Input with 150 coins
        tx_builder.add_input(
            &EnterpriseAddress::new(NetworkInfo::testnet().network_id(), &spend_cred).to_address(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(150)),
            None,
        );

        let addr_net_0 = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &spend_cred,
            &stake_cred,
        )
        .to_address();

        let (min_script, policy_id) = mint_script_and_policy(0);
        let name = AssetName::new(vec![0u8, 1, 2, 3]).unwrap();

        let amount_minted = to_bignum(1000);
        let amount_sent = to_bignum(500);

        // Adding mint of the asset - which should work as an input
        tx_builder.add_mint(
            &policy_id,
            &MintAssets::new_from_entry(&name, Int::new(&amount_minted)),
            Some(ScriptWitness::new_native_witness(&min_script)),
        );

        let mut ass = Assets::new();
        ass.insert(&name, &amount_sent);
        let mut mass = MultiAsset::new();
        mass.insert(&policy_id, &ass);

        // One coin and the minted asset goes into the output
        let mut output_amount = Value::new(&to_bignum(50));
        output_amount.set_multiasset(&mass);

        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&addr_net_0)
                    .next()
                    .unwrap()
                    .with_value(&output_amount)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw_key().hash());
        let change_addr = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &change_cred,
            &stake_cred,
        )
        .to_address();

        let added_change = tx_builder.add_change_if_needed(&change_addr).unwrap();
        assert!(added_change);
        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            2
        );

        // Change must be one remaining coin because fee is one constant coin
        let change = tx_builder
            .outputs
            .0
            .iter()
            .chain(tx_builder.change_outputs.0.iter())
            .collect_vec()
            .get(1)
            .unwrap()
            .amount();
        assert_eq!(change.coin(), to_bignum(99));
        assert!(change.multiasset().is_some());

        let change_assets = change.multiasset().unwrap();
        let change_asset = change_assets.get(&policy_id).unwrap();
        assert_eq!(
            change_asset.get(&name).unwrap(),
            amount_minted.checked_sub(&amount_sent).unwrap(),
        );
    }

    #[test]
    fn build_tx_with_native_assets_change() {
        let mut tx_builder = create_tx_builder_with_fee(&create_linear_fee(0, 1));
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();

        let policy_id = &PolicyID::from([0u8; 28]);
        let name = AssetName::new(vec![0u8, 1, 2, 3]).unwrap();

        let ma_input1 = 100;
        let ma_input2 = 200;
        let ma_output1 = 60;

        let multiassets = [ma_input1, ma_input2, ma_output1]
            .iter()
            .map(|input| {
                let mut multiasset = MultiAsset::new();
                multiasset.insert(policy_id, &{
                    let mut assets = Assets::new();
                    assets.insert(&name, &to_bignum(*input));
                    assets
                });
                multiasset
            })
            .collect::<Vec<MultiAsset>>();

        for (multiasset, ada) in multiassets
            .iter()
            .zip([100u64, 100].iter().cloned().map(to_bignum))
        {
            let mut input_amount = Value::new(&ada);
            input_amount.set_multiasset(multiasset);

            tx_builder.add_key_input(
                &&spend.to_raw_key().hash(),
                &TransactionInput::new(&genesis_id(), &0.into()),
                &input_amount,
            );
        }

        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw_key().hash());
        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw_key().hash());

        let addr_net_0 = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &spend_cred,
            &stake_cred,
        )
        .to_address();

        let mut output_amount = Value::new(&to_bignum(100));
        output_amount.set_multiasset(&multiassets[2]);

        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&addr_net_0)
                    .next()
                    .unwrap()
                    .with_value(&output_amount)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw_key().hash());
        let change_addr = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &change_cred,
            &stake_cred,
        )
        .to_address();

        let added_change = tx_builder.add_change_if_needed(&change_addr).unwrap();
        assert_eq!(added_change, true);
        let final_tx = tx_builder.build().unwrap();
        assert_eq!(final_tx.outputs().len(), 2);
        assert_eq!(
            final_tx
                .outputs()
                .get(1)
                .amount()
                .multiasset()
                .unwrap()
                .get(policy_id)
                .unwrap()
                .get(&name)
                .unwrap(),
            to_bignum(ma_input1 + ma_input2 - ma_output1)
        );
        assert_eq!(final_tx.outputs().get(1).amount().coin(), to_bignum(99));
    }

    #[test]
    fn build_tx_with_native_assets_change_and_purification() {
        let coin_per_utxo_word = to_bignum(1);
        // Prefer pure change!
        let mut tx_builder = create_tx_builder_with_fee_and_pure_change(&create_linear_fee(0, 1));
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();

        let policy_id = &PolicyID::from([0u8; 28]);
        let name = AssetName::new(vec![0u8, 1, 2, 3]).unwrap();

        let ma_input1 = 100;
        let ma_input2 = 200;
        let ma_output1 = 60;

        let multiassets = [ma_input1, ma_input2, ma_output1]
            .iter()
            .map(|input| {
                let mut multiasset = MultiAsset::new();
                multiasset.insert(policy_id, &{
                    let mut assets = Assets::new();
                    assets.insert(&name, &to_bignum(*input));
                    assets
                });
                multiasset
            })
            .collect::<Vec<MultiAsset>>();

        for (multiasset, ada) in multiassets
            .iter()
            .zip([100u64, 100].iter().cloned().map(to_bignum))
        {
            let mut input_amount = Value::new(&ada);
            input_amount.set_multiasset(multiasset);

            tx_builder.add_key_input(
                &&spend.to_raw_key().hash(),
                &TransactionInput::new(&genesis_id(), &0.into()),
                &input_amount,
            );
        }

        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw_key().hash());
        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw_key().hash());

        let addr_net_0 = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &spend_cred,
            &stake_cred,
        )
        .to_address();

        let mut output_amount = Value::new(&to_bignum(50));
        output_amount.set_multiasset(&multiassets[2]);

        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&addr_net_0)
                    .next()
                    .unwrap()
                    .with_value(&output_amount)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw_key().hash());
        let change_addr = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &change_cred,
            &stake_cred,
        )
        .to_address();

        let added_change = tx_builder.add_change_if_needed(&change_addr).unwrap();
        assert_eq!(added_change, true);
        let final_tx = tx_builder.build().unwrap();
        assert_eq!(final_tx.outputs().len(), 3);
        assert_eq!(final_tx.outputs().get(0).amount().coin(), to_bignum(50));
        assert_eq!(
            final_tx
                .outputs()
                .get(1)
                .amount()
                .multiasset()
                .unwrap()
                .get(policy_id)
                .unwrap()
                .get(&name)
                .unwrap(),
            to_bignum(ma_input1 + ma_input2 - ma_output1)
        );
        // The first change output that contains all the tokens contain minimum required Coin
        let min_coin_for_dirty_change = min_ada_required(
            &final_tx.outputs().get(1).amount(),
            false,
            &coin_per_utxo_word,
        )
        .unwrap();
        assert_eq!(
            final_tx.outputs().get(1).amount().coin(),
            min_coin_for_dirty_change
        );
        assert_eq!(final_tx.outputs().get(2).amount().coin(), to_bignum(110));
        assert_eq!(final_tx.outputs().get(2).amount().multiasset(), None);
    }

    #[test]
    fn build_tx_with_native_assets_change_and_no_purification_cuz_not_enough_pure_coin() {
        // Prefer pure change!
        let mut tx_builder = create_tx_builder_with_fee_and_pure_change(&create_linear_fee(1, 1));
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();

        let policy_id = &PolicyID::from([0u8; 28]);
        let name = AssetName::new(vec![0u8, 1, 2, 3]).unwrap();

        let ma_input1 = 100;
        let ma_input2 = 200;
        let ma_output1 = 60;

        let multiassets = [ma_input1, ma_input2, ma_output1]
            .iter()
            .map(|input| {
                let mut multiasset = MultiAsset::new();
                multiasset.insert(policy_id, &{
                    let mut assets = Assets::new();
                    assets.insert(&name, &to_bignum(*input));
                    assets
                });
                multiasset
            })
            .collect::<Vec<MultiAsset>>();

        for (multiasset, ada) in multiassets
            .iter()
            .zip([300u64, 300].iter().cloned().map(to_bignum))
        {
            let mut input_amount = Value::new(&ada);
            input_amount.set_multiasset(multiasset);

            tx_builder.add_key_input(
                &&spend.to_raw_key().hash(),
                &TransactionInput::new(&genesis_id(), &0.into()),
                &input_amount,
            );
        }

        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw_key().hash());
        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw_key().hash());

        let addr_net_0 = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &spend_cred,
            &stake_cred,
        )
        .to_address();

        let mut output_amount = Value::new(&to_bignum(100));
        output_amount.set_multiasset(&multiassets[2]);

        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&addr_net_0)
                    .next()
                    .unwrap()
                    .with_value(&output_amount)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw_key().hash());
        let change_addr = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &change_cred,
            &stake_cred,
        )
        .to_address();

        let added_change = tx_builder.add_change_if_needed(&change_addr).unwrap();
        assert_eq!(added_change, true);
        let final_tx = tx_builder.build().unwrap();
        assert_eq!(final_tx.outputs().len(), 2);
        assert_eq!(final_tx.outputs().get(0).amount().coin(), to_bignum(100));
        assert_eq!(
            final_tx
                .outputs()
                .get(1)
                .amount()
                .multiasset()
                .unwrap()
                .get(policy_id)
                .unwrap()
                .get(&name)
                .unwrap(),
            to_bignum(ma_input1 + ma_input2 - ma_output1)
        );
        // The single change output contains more Coin then minimal utxo value
        // But not enough to cover the additional fee for a separate output
        assert_eq!(final_tx.outputs().get(1).amount().coin(), to_bignum(101));
    }

    #[test]
    #[should_panic]
    fn build_tx_leftover_assets() {
        let mut tx_builder = create_default_tx_builder();
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();

        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw_key().hash());
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw_key().hash());
        let addr_net_0 = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &spend_cred,
            &stake_cred,
        )
        .to_address();

        // add an input that contains an asset not present in the output
        let policy_id = &PolicyID::from([0u8; 28]);
        let name = AssetName::new(vec![0u8, 1, 2, 3]).unwrap();
        let mut input_amount = Value::new(&to_bignum(1_000_000));
        let mut input_multiasset = MultiAsset::new();
        input_multiasset.insert(policy_id, &{
            let mut assets = Assets::new();
            assets.insert(&name, &to_bignum(100));
            assets
        });
        input_amount.set_multiasset(&input_multiasset);
        tx_builder.add_key_input(
            &spend.to_raw_key().hash(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &input_amount,
        );

        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&addr_net_0)
                    .next()
                    .unwrap()
                    .with_coin(&to_bignum(880_000))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        tx_builder.set_ttl(&1000.into());

        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw_key().hash());
        let change_addr = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &change_cred,
            &stake_cred,
        )
        .to_address();
        let added_change = tx_builder.add_change_if_needed(&change_addr);
        assert!(!added_change.unwrap());
        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            1
        );
        assert_eq!(
            tx_builder
                .get_explicit_input()
                .unwrap()
                .checked_add(&tx_builder.get_implicit_input().unwrap())
                .unwrap(),
            tx_builder
                .get_explicit_output()
                .unwrap()
                .checked_add(&Value::new(&tx_builder.get_fee_if_set().unwrap()))
                .unwrap()
        );
        let _final_tx = tx_builder.build(); // just test that it doesn't throw
    }

    #[test]
    fn build_tx_burn_less_than_min_ada() {
        // with this mainnet value we should end up with a final min_ada_required of just under 1_000_000
        let mut tx_builder = create_reallistic_tx_builder();

        let output_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZD9QQf2ZrcYV34pYJwxK4vqXaF8EXkup1eYH73zUScHReM42b",
        )
        .unwrap();
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&output_addr.to_address())
                    .next()
                    .unwrap()
                    .with_value(&Value::new(&to_bignum(2_000_000)))
                    .build()
                    .unwrap(),
            )
            .unwrap();

        tx_builder.add_input(
            &ByronAddress::from_base58(
                "Ae2tdPwUPEZ5uzkzh1o2DHECiUi3iugvnnKHRisPgRRP3CTF4KCMvy54Xd3",
            )
            .unwrap()
            .to_address(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(2_400_000)),
            None,
        );

        tx_builder.set_ttl(&1.into());

        let change_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZGUEsuMAhvDcy94LKsZxDjCbgaiBBMgYpR8sKf96xJmit7Eho",
        )
        .unwrap();
        let added_change = tx_builder.add_change_if_needed(&change_addr.to_address());
        assert!(!added_change.unwrap());
        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            1
        );
        assert_eq!(
            tx_builder
                .get_explicit_input()
                .unwrap()
                .checked_add(&tx_builder.get_implicit_input().unwrap())
                .unwrap(),
            tx_builder
                .get_explicit_output()
                .unwrap()
                .checked_add(&Value::new(&tx_builder.get_fee_if_set().unwrap()))
                .unwrap()
        );
        let _final_tx = tx_builder.build(); // just test that it doesn't throw
    }

    #[test]
    fn build_tx_burn_empty_assets() {
        let mut tx_builder = create_reallistic_tx_builder();

        let output_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZD9QQf2ZrcYV34pYJwxK4vqXaF8EXkup1eYH73zUScHReM42b",
        )
        .unwrap();
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&output_addr.to_address())
                    .next()
                    .unwrap()
                    .with_value(&Value::new(&to_bignum(2_000_000)))
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let mut input_value = Value::new(&to_bignum(2_400_000));
        input_value.set_multiasset(&MultiAsset::new());
        tx_builder.add_input(
            &ByronAddress::from_base58(
                "Ae2tdPwUPEZ5uzkzh1o2DHECiUi3iugvnnKHRisPgRRP3CTF4KCMvy54Xd3",
            )
            .unwrap()
            .to_address(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &input_value,
            None,
        );

        tx_builder.set_ttl(&1.into());

        let change_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZGUEsuMAhvDcy94LKsZxDjCbgaiBBMgYpR8sKf96xJmit7Eho",
        )
        .unwrap();
        let added_change = tx_builder.add_change_if_needed(&change_addr.to_address());
        assert!(!added_change.unwrap());
        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            1
        );
        assert_eq!(
            tx_builder
                .get_explicit_input()
                .unwrap()
                .checked_add(&tx_builder.get_implicit_input().unwrap())
                .unwrap()
                .coin(),
            tx_builder
                .get_explicit_output()
                .unwrap()
                .checked_add(&Value::new(&tx_builder.get_fee_if_set().unwrap()))
                .unwrap()
                .coin()
        );
        let _final_tx = tx_builder.build(); // just test that it doesn't throw
    }

    #[test]
    fn build_tx_no_useless_multiasset() {
        let mut tx_builder = create_reallistic_tx_builder();

        let policy_id = &PolicyID::from([0u8; 28]);
        let name = AssetName::new(vec![0u8, 1, 2, 3]).unwrap();

        // add an output that uses up all the token but leaves ADA
        let mut input_amount = Value::new(&to_bignum(5_000_000));
        let mut input_multiasset = MultiAsset::new();
        input_multiasset.insert(policy_id, &{
            let mut assets = Assets::new();
            assets.insert(&name, &to_bignum(100));
            assets
        });
        input_amount.set_multiasset(&input_multiasset);

        tx_builder.add_input(
            &ByronAddress::from_base58(
                "Ae2tdPwUPEZ5uzkzh1o2DHECiUi3iugvnnKHRisPgRRP3CTF4KCMvy54Xd3",
            )
            .unwrap()
            .to_address(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &input_amount,
            None,
        );

        // add an input that contains an asset & ADA
        let mut output_amount = Value::new(&to_bignum(2_000_000));
        let mut output_multiasset = MultiAsset::new();
        output_multiasset.insert(policy_id, &{
            let mut assets = Assets::new();
            assets.insert(&name, &to_bignum(100));
            assets
        });
        output_amount.set_multiasset(&output_multiasset);

        let output_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZD9QQf2ZrcYV34pYJwxK4vqXaF8EXkup1eYH73zUScHReM42b",
        )
        .unwrap();
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&output_addr.to_address())
                    .next()
                    .unwrap()
                    .with_value(&output_amount)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        tx_builder.set_ttl(&1.into());

        let change_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZGUEsuMAhvDcy94LKsZxDjCbgaiBBMgYpR8sKf96xJmit7Eho",
        )
        .unwrap();
        let added_change = tx_builder.add_change_if_needed(&change_addr.to_address());
        assert!(added_change.unwrap());
        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            2
        );
        let final_tx = tx_builder.build().unwrap();
        let change_output = final_tx.outputs().get(1);
        let change_assets = change_output.amount().multiasset();

        // since all tokens got sent in the output
        // the change should be only ADA and not have any multiasset struct in it
        assert!(change_assets.is_none());
    }

    fn create_multiasset() -> (MultiAsset, [ScriptHash; 3], [AssetName; 3]) {
        let policy_ids = [
            PolicyID::from([0u8; 28]),
            PolicyID::from([1u8; 28]),
            PolicyID::from([2u8; 28]),
        ];
        let names = [
            AssetName::new(vec![99u8; 32]).unwrap(),
            AssetName::new(vec![0u8, 1, 2, 3]).unwrap(),
            AssetName::new(vec![4u8, 5, 6, 7, 8, 9]).unwrap(),
        ];
        let multiasset = policy_ids.iter().zip(names.iter()).fold(
            MultiAsset::new(),
            |mut acc, (policy_id, name)| {
                acc.insert(policy_id, &{
                    let mut assets = Assets::new();
                    assets.insert(&name, &to_bignum(500));
                    assets
                });
                acc
            },
        );
        return (multiasset, policy_ids, names);
    }

    #[test]
    fn build_tx_add_change_split_nfts() {
        let max_value_size = 100; // super low max output size to test with fewer assets
        let mut tx_builder =
            create_tx_builder_with_fee_and_val_size(&create_linear_fee(0, 1), max_value_size);

        let (multiasset, policy_ids, names) = create_multiasset();

        let mut input_value = Value::new(&to_bignum(1000));
        input_value.set_multiasset(&multiasset);

        tx_builder.add_input(
            &ByronAddress::from_base58(
                "Ae2tdPwUPEZ5uzkzh1o2DHECiUi3iugvnnKHRisPgRRP3CTF4KCMvy54Xd3",
            )
            .unwrap()
            .to_address(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &input_value,
            None,
        );

        let output_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZD9QQf2ZrcYV34pYJwxK4vqXaF8EXkup1eYH73zUScHReM42b",
        )
        .unwrap()
        .to_address();
        let output_amount = Value::new(&to_bignum(100));

        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&output_addr)
                    .next()
                    .unwrap()
                    .with_value(&output_amount)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let change_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZGUEsuMAhvDcy94LKsZxDjCbgaiBBMgYpR8sKf96xJmit7Eho",
        )
        .unwrap()
        .to_address();

        let added_change = tx_builder.add_change_if_needed(&change_addr).unwrap();
        assert_eq!(added_change, true);
        let final_tx = tx_builder.build().unwrap();
        assert_eq!(final_tx.outputs().len(), 3);
        for (policy_id, asset_name) in policy_ids.iter().zip(names.iter()) {
            assert!(final_tx
                .outputs
                .0
                .iter()
                .find(|output| output.amount.multiasset.as_ref().map_or_else(
                    || false,
                    |ma| ma
                        .0
                        .iter()
                        .find(|(pid, a)| *pid == policy_id
                            && a.0.iter().find(|(name, _)| *name == asset_name).is_some())
                        .is_some()
                ))
                .is_some());
        }
        for output in final_tx.outputs.0.iter() {
            assert!(output.amount.to_bytes().len() <= max_value_size as usize);
        }
    }

    #[test]
    fn build_tx_too_big_output() {
        let mut tx_builder = create_tx_builder_with_fee_and_val_size(&create_linear_fee(0, 1), 10);

        tx_builder.add_input(
            &ByronAddress::from_base58(
                "Ae2tdPwUPEZ5uzkzh1o2DHECiUi3iugvnnKHRisPgRRP3CTF4KCMvy54Xd3",
            )
            .unwrap()
            .to_address(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(500)),
            None,
        );

        let output_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZD9QQf2ZrcYV34pYJwxK4vqXaF8EXkup1eYH73zUScHReM42b",
        )
        .unwrap()
        .to_address();
        let mut output_amount = Value::new(&to_bignum(50));
        output_amount.set_multiasset(&create_multiasset().0);

        assert!(tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&output_addr)
                    .next()
                    .unwrap()
                    .with_value(&output_amount)
                    .build()
                    .unwrap(),
            )
            .is_err());
    }

    #[test]
    fn build_tx_add_change_nfts_not_enough_ada() {
        let mut tx_builder = create_tx_builder_with_fee_and_val_size(
            &create_linear_fee(0, 1),
            150, // super low max output size to test with fewer assets
        );

        let policy_ids = [
            PolicyID::from([0u8; 28]),
            PolicyID::from([1u8; 28]),
            PolicyID::from([2u8; 28]),
        ];
        let names = [
            AssetName::new(vec![99u8; 32]).unwrap(),
            AssetName::new(vec![0u8, 1, 2, 3]).unwrap(),
            AssetName::new(vec![4u8, 5, 6, 7, 8, 9]).unwrap(),
        ];

        let multiasset = policy_ids.iter().zip(names.iter()).fold(
            MultiAsset::new(),
            |mut acc, (policy_id, name)| {
                acc.insert(policy_id, &{
                    let mut assets = Assets::new();
                    assets.insert(&name, &to_bignum(500));
                    assets
                });
                acc
            },
        );

        let mut input_value = Value::new(&to_bignum(58));
        input_value.set_multiasset(&multiasset);

        tx_builder.add_input(
            &ByronAddress::from_base58(
                "Ae2tdPwUPEZ5uzkzh1o2DHECiUi3iugvnnKHRisPgRRP3CTF4KCMvy54Xd3",
            )
            .unwrap()
            .to_address(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &input_value,
            None,
        );

        let output_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZD9QQf2ZrcYV34pYJwxK4vqXaF8EXkup1eYH73zUScHReM42b",
        )
        .unwrap()
        .to_address();
        let output_amount = Value::new(&to_bignum(59));

        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&output_addr)
                    .next()
                    .unwrap()
                    .with_value(&output_amount)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let change_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZGUEsuMAhvDcy94LKsZxDjCbgaiBBMgYpR8sKf96xJmit7Eho",
        )
        .unwrap()
        .to_address();

        assert!(tx_builder.add_change_if_needed(&change_addr).is_err())
    }

    fn make_input(input_hash_byte: u8, value: Value) -> TransactionUnspentOutput {
        TransactionUnspentOutput::new(
            &TransactionInput::new(&TransactionHash::from([input_hash_byte; 32]), &0.into()),
            &TransactionOutputBuilder::new()
                .with_address(
                    &Address::from_bech32(
                        "addr1vyy6nhfyks7wdu3dudslys37v252w2nwhv0fw2nfawemmnqs6l44z",
                    )
                    .unwrap(),
                )
                .next()
                .unwrap()
                .with_value(&value)
                .build()
                .unwrap(),
        )
    }

    #[test]
    fn tx_builder_cip2_largest_first_increasing_fees() {
        // we have a = 1 to test increasing fees when more inputs are added
        let mut tx_builder = create_tx_builder_with_fee(&create_linear_fee(1, 0));
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(
                        &Address::from_bech32(
                            "addr1vyy6nhfyks7wdu3dudslys37v252w2nwhv0fw2nfawemmnqs6l44z",
                        )
                        .unwrap(),
                    )
                    .next()
                    .unwrap()
                    .with_coin(&to_bignum(1000))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let mut available_inputs = TransactionUnspentOutputs::new();
        available_inputs.add(&make_input(0u8, Value::new(&to_bignum(150))));
        available_inputs.add(&make_input(1u8, Value::new(&to_bignum(200))));
        available_inputs.add(&make_input(2u8, Value::new(&to_bignum(800))));
        available_inputs.add(&make_input(3u8, Value::new(&to_bignum(400))));
        available_inputs.add(&make_input(4u8, Value::new(&to_bignum(100))));
        tx_builder
            .add_inputs_from(&available_inputs, CoinSelectionStrategyCIP2::LargestFirst)
            .unwrap();
        let change_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZGUEsuMAhvDcy94LKsZxDjCbgaiBBMgYpR8sKf96xJmit7Eho",
        )
        .unwrap()
        .to_address();
        let change_added = tx_builder.add_change_if_needed(&change_addr).unwrap();
        assert!(change_added);
        let tx = tx_builder.build().unwrap();
        // change needed
        assert_eq!(2, tx.outputs().len());
        assert_eq!(3, tx.inputs().len());
        // confirm order of only what is necessary
        assert_eq!(2u8, tx.inputs().get(0).transaction_id().0[0]);
        assert_eq!(3u8, tx.inputs().get(1).transaction_id().0[0]);
        assert_eq!(1u8, tx.inputs().get(2).transaction_id().0[0]);
    }

    #[test]
    fn tx_builder_cip2_largest_first_static_fees() {
        // we have a = 0 so we know adding inputs/outputs doesn't change the fee so we can analyze more
        let mut tx_builder = create_tx_builder_with_fee(&create_linear_fee(0, 0));
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(
                        &Address::from_bech32(
                            "addr1vyy6nhfyks7wdu3dudslys37v252w2nwhv0fw2nfawemmnqs6l44z",
                        )
                        .unwrap(),
                    )
                    .next()
                    .unwrap()
                    .with_coin(&to_bignum(1200))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let mut available_inputs = TransactionUnspentOutputs::new();
        available_inputs.add(&make_input(0u8, Value::new(&to_bignum(150))));
        available_inputs.add(&make_input(1u8, Value::new(&to_bignum(200))));
        available_inputs.add(&make_input(2u8, Value::new(&to_bignum(800))));
        available_inputs.add(&make_input(3u8, Value::new(&to_bignum(400))));
        available_inputs.add(&make_input(4u8, Value::new(&to_bignum(100))));
        tx_builder
            .add_inputs_from(&available_inputs, CoinSelectionStrategyCIP2::LargestFirst)
            .unwrap();
        let change_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZGUEsuMAhvDcy94LKsZxDjCbgaiBBMgYpR8sKf96xJmit7Eho",
        )
        .unwrap()
        .to_address();
        let change_added = tx_builder.add_change_if_needed(&change_addr).unwrap();
        assert!(!change_added);
        let tx = tx_builder.build().unwrap();
        // change not needed - should be exact
        assert_eq!(1, tx.outputs().len());
        assert_eq!(2, tx.inputs().len());
        // confirm order of only what is necessary
        assert_eq!(2u8, tx.inputs().get(0).transaction_id().0[0]);
        assert_eq!(3u8, tx.inputs().get(1).transaction_id().0[0]);
    }

    #[test]
    fn tx_builder_cip2_largest_first_multiasset() {
        // we have a = 0 so we know adding inputs/outputs doesn't change the fee so we can analyze more
        let mut tx_builder = create_tx_builder_with_fee(&create_linear_fee(0, 0));
        let pid1 = PolicyID::from([1u8; 28]);
        let pid2 = PolicyID::from([2u8; 28]);
        let asset_name1 = AssetName::new(vec![1u8; 8]).unwrap();
        let asset_name2 = AssetName::new(vec![2u8; 11]).unwrap();
        let asset_name3 = AssetName::new(vec![3u8; 9]).unwrap();

        let mut output_value = Value::new(&to_bignum(415));
        let mut output_ma = MultiAsset::new();
        output_ma.set_asset(&pid1, &asset_name1, to_bignum(5));
        output_ma.set_asset(&pid1, &asset_name2, to_bignum(1));
        output_ma.set_asset(&pid2, &asset_name2, to_bignum(2));
        output_ma.set_asset(&pid2, &asset_name3, to_bignum(4));
        output_value.set_multiasset(&output_ma);
        tx_builder
            .add_output(&TransactionOutput::new(
                &Address::from_bech32("addr1vyy6nhfyks7wdu3dudslys37v252w2nwhv0fw2nfawemmnqs6l44z")
                    .unwrap(),
                &output_value,
            ))
            .unwrap();

        let mut available_inputs = TransactionUnspentOutputs::new();
        // should not be taken
        available_inputs.add(&make_input(0u8, Value::new(&to_bignum(150))));

        // should not be taken
        let mut input1 = make_input(1u8, Value::new(&to_bignum(200)));
        let mut ma1 = MultiAsset::new();
        ma1.set_asset(&pid1, &asset_name1, to_bignum(10));
        ma1.set_asset(&pid1, &asset_name2, to_bignum(1));
        ma1.set_asset(&pid2, &asset_name2, to_bignum(2));
        input1.output.amount.set_multiasset(&ma1);
        available_inputs.add(&input1);

        // taken first to satisfy pid1:asset_name1 (but also satisfies pid2:asset_name3)
        let mut input2 = make_input(2u8, Value::new(&to_bignum(10)));
        let mut ma2 = MultiAsset::new();
        ma2.set_asset(&pid1, &asset_name1, to_bignum(20));
        ma2.set_asset(&pid2, &asset_name3, to_bignum(4));
        input2.output.amount.set_multiasset(&ma2);
        available_inputs.add(&input2);

        // taken second to satisfy pid1:asset_name2 (but also satisfies pid2:asset_name1)
        let mut input3 = make_input(3u8, Value::new(&to_bignum(50)));
        let mut ma3 = MultiAsset::new();
        ma3.set_asset(&pid2, &asset_name1, to_bignum(5));
        ma3.set_asset(&pid1, &asset_name2, to_bignum(15));
        input3.output.amount.multiasset = Some(ma3);
        available_inputs.add(&input3);

        // should not be taken either
        let mut input4 = make_input(4u8, Value::new(&to_bignum(10)));
        let mut ma4 = MultiAsset::new();
        ma4.set_asset(&pid1, &asset_name1, to_bignum(10));
        ma4.set_asset(&pid1, &asset_name2, to_bignum(10));
        input4.output.amount.multiasset = Some(ma4);
        available_inputs.add(&input4);

        // taken third to satisfy pid2:asset_name_2
        let mut input5 = make_input(5u8, Value::new(&to_bignum(10)));
        let mut ma5 = MultiAsset::new();
        ma5.set_asset(&pid1, &asset_name2, to_bignum(10));
        ma5.set_asset(&pid2, &asset_name2, to_bignum(3));
        input5.output.amount.multiasset = Some(ma5);
        available_inputs.add(&input5);

        // should be taken to get enough ADA
        let input6 = make_input(6u8, Value::new(&to_bignum(400)));
        available_inputs.add(&input6);

        // should not be taken
        available_inputs.add(&make_input(7u8, Value::new(&to_bignum(100))));
        tx_builder
            .add_inputs_from(
                &available_inputs,
                CoinSelectionStrategyCIP2::LargestFirstMultiAsset,
            )
            .unwrap();
        let change_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZGUEsuMAhvDcy94LKsZxDjCbgaiBBMgYpR8sKf96xJmit7Eho",
        )
        .unwrap()
        .to_address();
        let change_added = tx_builder.add_change_if_needed(&change_addr).unwrap();
        assert!(change_added);
        let tx = tx_builder.build().unwrap();

        assert_eq!(2, tx.outputs().len());
        assert_eq!(4, tx.inputs().len());
        // check order expected per-asset
        assert_eq!(2u8, tx.inputs().get(0).transaction_id().0[0]);
        assert_eq!(3u8, tx.inputs().get(1).transaction_id().0[0]);
        assert_eq!(5u8, tx.inputs().get(2).transaction_id().0[0]);
        assert_eq!(6u8, tx.inputs().get(3).transaction_id().0[0]);

        let change = tx.outputs().get(1).amount;
        assert_eq!(from_bignum(&change.coin), 55);
        let change_ma = change.multiasset().unwrap();
        assert_eq!(15, from_bignum(&change_ma.get_asset(&pid1, &asset_name1)));
        assert_eq!(24, from_bignum(&change_ma.get_asset(&pid1, &asset_name2)));
        assert_eq!(1, from_bignum(&change_ma.get_asset(&pid2, &asset_name2)));
        assert_eq!(0, from_bignum(&change_ma.get_asset(&pid2, &asset_name3)));
        let expected_input = input2
            .output
            .amount
            .checked_add(&input3.output.amount)
            .unwrap()
            .checked_add(&input5.output.amount)
            .unwrap()
            .checked_add(&input6.output.amount)
            .unwrap();
        let expected_change = expected_input.checked_sub(&output_value).unwrap();
        assert_eq!(expected_change, change);
    }

    #[test]
    fn tx_builder_cip2_random_improve_multiasset() {
        let linear_fee = LinearFee::new(&to_bignum(0), &to_bignum(0));
        let mut tx_builder = create_tx_builder_with_fee(&create_linear_fee(0, 0));
        let pid1 = PolicyID::from([1u8; 28]);
        let pid2 = PolicyID::from([2u8; 28]);
        let asset_name1 = AssetName::new(vec![1u8; 8]).unwrap();
        let asset_name2 = AssetName::new(vec![2u8; 11]).unwrap();
        let asset_name3 = AssetName::new(vec![3u8; 9]).unwrap();

        let mut output_value = Value::new(&to_bignum(415));
        let mut output_ma = MultiAsset::new();
        output_ma.set_asset(&pid1, &asset_name1, to_bignum(5));
        output_ma.set_asset(&pid1, &asset_name2, to_bignum(1));
        output_ma.set_asset(&pid2, &asset_name2, to_bignum(2));
        output_ma.set_asset(&pid2, &asset_name3, to_bignum(4));
        output_value.set_multiasset(&output_ma);
        tx_builder
            .add_output(&TransactionOutput::new(
                &Address::from_bech32("addr1vyy6nhfyks7wdu3dudslys37v252w2nwhv0fw2nfawemmnqs6l44z")
                    .unwrap(),
                &output_value,
            ))
            .unwrap();

        let mut available_inputs = TransactionUnspentOutputs::new();
        available_inputs.add(&make_input(0u8, Value::new(&to_bignum(150))));

        let mut input1 = make_input(1u8, Value::new(&to_bignum(200)));
        let mut ma1 = MultiAsset::new();
        ma1.set_asset(&pid1, &asset_name1, to_bignum(10));
        ma1.set_asset(&pid1, &asset_name2, to_bignum(1));
        ma1.set_asset(&pid2, &asset_name2, to_bignum(2));
        input1.output.amount.set_multiasset(&ma1);
        available_inputs.add(&input1);

        let mut input2 = make_input(2u8, Value::new(&to_bignum(10)));
        let mut ma2 = MultiAsset::new();
        ma2.set_asset(&pid1, &asset_name1, to_bignum(20));
        ma2.set_asset(&pid2, &asset_name3, to_bignum(4));
        input2.output.amount.set_multiasset(&ma2);
        available_inputs.add(&input2);

        let mut input3 = make_input(3u8, Value::new(&to_bignum(50)));
        let mut ma3 = MultiAsset::new();
        ma3.set_asset(&pid2, &asset_name1, to_bignum(5));
        ma3.set_asset(&pid1, &asset_name2, to_bignum(15));
        input3.output.amount.multiasset = Some(ma3);
        available_inputs.add(&input3);

        let mut input4 = make_input(4u8, Value::new(&to_bignum(10)));
        let mut ma4 = MultiAsset::new();
        ma4.set_asset(&pid1, &asset_name1, to_bignum(10));
        ma4.set_asset(&pid1, &asset_name2, to_bignum(10));
        input4.output.amount.multiasset = Some(ma4);
        available_inputs.add(&input4);

        let mut input5 = make_input(5u8, Value::new(&to_bignum(10)));
        let mut ma5 = MultiAsset::new();
        ma5.set_asset(&pid1, &asset_name2, to_bignum(10));
        ma5.set_asset(&pid2, &asset_name2, to_bignum(3));
        input5.output.amount.multiasset = Some(ma5);
        available_inputs.add(&input5);

        let input6 = make_input(6u8, Value::new(&to_bignum(400)));
        available_inputs.add(&input6);
        available_inputs.add(&make_input(7u8, Value::new(&to_bignum(100))));

        let mut input8 = make_input(8u8, Value::new(&to_bignum(10)));
        let mut ma8 = MultiAsset::new();
        ma8.set_asset(&pid2, &asset_name2, to_bignum(10));
        input8.output.amount.multiasset = Some(ma8);
        available_inputs.add(&input8);

        let mut input9 = make_input(9u8, Value::new(&to_bignum(10)));
        let mut ma9 = MultiAsset::new();
        ma9.set_asset(&pid2, &asset_name3, to_bignum(10));
        input9.output.amount.multiasset = Some(ma9);
        available_inputs.add(&input9);

        tx_builder
            .add_inputs_from(
                &available_inputs,
                CoinSelectionStrategyCIP2::RandomImproveMultiAsset,
            )
            .unwrap();
        let change_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZGUEsuMAhvDcy94LKsZxDjCbgaiBBMgYpR8sKf96xJmit7Eho",
        )
        .unwrap()
        .to_address();
        let change_added = tx_builder.add_change_if_needed(&change_addr).unwrap();
        assert!(change_added);
        let tx = tx_builder.build().unwrap();

        assert_eq!(2, tx.outputs().len());

        let input_total = tx_builder.get_explicit_input().unwrap();
        assert!(input_total >= output_value);
    }

    #[test]
    fn tx_builder_cip2_random_improve() {
        // we have a = 1 to test increasing fees when more inputs are added
        let mut tx_builder = create_tx_builder_with_fee(&create_linear_fee(1, 0));
        const COST: u64 = 10000;
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(
                        &Address::from_bech32(
                            "addr1vyy6nhfyks7wdu3dudslys37v252w2nwhv0fw2nfawemmnqs6l44z",
                        )
                        .unwrap(),
                    )
                    .next()
                    .unwrap()
                    .with_coin(&to_bignum(COST))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let mut available_inputs = TransactionUnspentOutputs::new();
        available_inputs.add(&make_input(0u8, Value::new(&to_bignum(1500))));
        available_inputs.add(&make_input(1u8, Value::new(&to_bignum(2000))));
        available_inputs.add(&make_input(2u8, Value::new(&to_bignum(8000))));
        available_inputs.add(&make_input(3u8, Value::new(&to_bignum(4000))));
        available_inputs.add(&make_input(4u8, Value::new(&to_bignum(1000))));
        available_inputs.add(&make_input(5u8, Value::new(&to_bignum(2000))));
        available_inputs.add(&make_input(6u8, Value::new(&to_bignum(1500))));
        let add_inputs_res =
            tx_builder.add_inputs_from(&available_inputs, CoinSelectionStrategyCIP2::RandomImprove);
        assert!(add_inputs_res.is_ok(), "{:?}", add_inputs_res.err());
        let change_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZGUEsuMAhvDcy94LKsZxDjCbgaiBBMgYpR8sKf96xJmit7Eho",
        )
        .unwrap()
        .to_address();
        let add_change_res = tx_builder.add_change_if_needed(&change_addr);
        assert!(add_change_res.is_ok(), "{:?}", add_change_res.err());
        let tx_build_res = tx_builder.build();
        assert!(tx_build_res.is_ok(), "{:?}", tx_build_res.err());
        let tx = tx_build_res.unwrap();
        // we need to look up the values to ensure there's enough
        let mut input_values = BTreeMap::new();
        for utxo in available_inputs.0.iter() {
            input_values.insert(utxo.input.transaction_id(), utxo.output.amount.clone());
        }
        let mut encountered = std::collections::HashSet::new();
        let mut input_total = Value::new(&Coin::zero());
        for input in tx.inputs.0.iter() {
            let txid = input.transaction_id();
            if !encountered.insert(txid.clone()) {
                panic!("Input {:?} duplicated", txid);
            }
            let value = input_values.get(&txid).unwrap();
            input_total = input_total.checked_add(value).unwrap();
        }
        assert!(
            input_total
                >= Value::new(
                    &tx_builder
                        .min_fee()
                        .unwrap()
                        .checked_add(&to_bignum(COST))
                        .unwrap()
                )
        );
    }

    #[test]
    fn tx_builder_cip2_random_improve_when_using_all_available_inputs() {
        // we have a = 1 to test increasing fees when more inputs are added
        let linear_fee = LinearFee::new(&to_bignum(1), &to_bignum(0));
        let cfg = TransactionBuilderConfigBuilder::new()
            .fee_algo(&linear_fee)
            .pool_deposit(&to_bignum(0))
            .key_deposit(&to_bignum(0))
            .max_value_size(9999)
            .max_tx_size(9999)
            .coins_per_utxo_word(&Coin::zero())
            .ex_unit_prices(&ExUnitPrices::from_float(0.0, 0.0))
            .build()
            .unwrap();
        let mut tx_builder = TransactionBuilder::new(&cfg);
        const COST: u64 = 1000;
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(
                        &Address::from_bech32(
                            "addr1vyy6nhfyks7wdu3dudslys37v252w2nwhv0fw2nfawemmnqs6l44z",
                        )
                        .unwrap(),
                    )
                    .next()
                    .unwrap()
                    .with_coin(&to_bignum(COST))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let mut available_inputs = TransactionUnspentOutputs::new();
        available_inputs.add(&make_input(1u8, Value::new(&to_bignum(800))));
        available_inputs.add(&make_input(2u8, Value::new(&to_bignum(800))));
        let add_inputs_res =
            tx_builder.add_inputs_from(&available_inputs, CoinSelectionStrategyCIP2::RandomImprove);
        assert!(add_inputs_res.is_ok(), "{:?}", add_inputs_res.err());
    }

    #[test]
    fn tx_builder_cip2_random_improve_adds_enough_for_fees() {
        // we have a = 1 to test increasing fees when more inputs are added
        let linear_fee = LinearFee::new(&to_bignum(1), &to_bignum(0));
        let cfg = TransactionBuilderConfigBuilder::new()
            .fee_algo(&linear_fee)
            .pool_deposit(&to_bignum(0))
            .key_deposit(&to_bignum(0))
            .max_value_size(9999)
            .max_tx_size(9999)
            .coins_per_utxo_word(&Coin::zero())
            .ex_unit_prices(&ExUnitPrices::from_float(0.0, 0.0))
            .build()
            .unwrap();
        let mut tx_builder = TransactionBuilder::new(&cfg);
        const COST: u64 = 100;
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(
                        &Address::from_bech32(
                            "addr1vyy6nhfyks7wdu3dudslys37v252w2nwhv0fw2nfawemmnqs6l44z",
                        )
                        .unwrap(),
                    )
                    .next()
                    .unwrap()
                    .with_coin(&to_bignum(COST))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(tx_builder.min_fee().unwrap(), to_bignum(53));
        let mut available_inputs = TransactionUnspentOutputs::new();
        available_inputs.add(&make_input(1u8, Value::new(&to_bignum(150))));
        available_inputs.add(&make_input(2u8, Value::new(&to_bignum(150))));
        available_inputs.add(&make_input(3u8, Value::new(&to_bignum(150))));
        let add_inputs_res =
            tx_builder.add_inputs_from(&available_inputs, CoinSelectionStrategyCIP2::RandomImprove);
        assert!(add_inputs_res.is_ok(), "{:?}", add_inputs_res.err());
        assert_eq!(tx_builder.min_fee().unwrap(), to_bignum(264));
        let change_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZGUEsuMAhvDcy94LKsZxDjCbgaiBBMgYpR8sKf96xJmit7Eho",
        )
        .unwrap()
        .to_address();
        let add_change_res = tx_builder.add_change_if_needed(&change_addr);
        assert!(add_change_res.is_ok(), "{:?}", add_change_res.err());
    }

    #[test]
    fn build_tx_pay_to_multisig() {
        let mut tx_builder = create_tx_builder_with_fee(&create_linear_fee(10, 2));
        let spend = root_key_15()
            .derive(harden(1854))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();

        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();

        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw_key().hash());
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw_key().hash());

        let addr_net_0 = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &spend_cred,
            &stake_cred,
        )
        .to_address();

        tx_builder.add_key_input(
            &spend.to_raw_key().hash(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(1_000_000)),
        );
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&addr_net_0)
                    .next()
                    .unwrap()
                    .with_coin(&to_bignum(999_000))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        tx_builder.set_ttl(&1000.into());
        tx_builder.set_fee(&to_bignum(1_000));

        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            1
        );
        assert_eq!(
            tx_builder
                .get_explicit_input()
                .unwrap()
                .checked_add(&tx_builder.get_implicit_input().unwrap())
                .unwrap(),
            tx_builder
                .get_explicit_output()
                .unwrap()
                .checked_add(&Value::new(&tx_builder.get_fee_if_set().unwrap()))
                .unwrap()
        );

        let _final_tx = tx_builder.build().unwrap();
        let _deser_t = TransactionBody::from_bytes(_final_tx.to_bytes()).unwrap();

        assert_eq!(_deser_t.to_bytes(), _final_tx.to_bytes());
    }

    fn build_full_tx(
        body: &TransactionBody,
        witness_set: &TransactionWitnessSet,
        auxiliary_data: Option<AuxiliaryData>,
    ) -> Transaction {
        return Transaction::new(body, witness_set, auxiliary_data);
    }

    #[test]
    fn build_tx_multisig_spend_1on1_unsigned() {
        let mut tx_builder = create_tx_builder_with_fee(&create_linear_fee(10, 2));

        let spend = root_key_15() //multisig
            .derive(harden(1854))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let stake = root_key_15() //multisig
            .derive(harden(1854))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();

        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();

        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw_key().hash());
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw_key().hash());
        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw_key().hash());
        let addr_multisig = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &spend_cred,
            &stake_cred,
        )
        .to_address();
        let addr_output = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &change_cred,
            &stake_cred,
        )
        .to_address();

        tx_builder.add_input(
            &addr_multisig,
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(1_000_000)),
            None,
        );

        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&addr_output)
                    .next()
                    .unwrap()
                    .with_coin(&to_bignum(999_000))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        tx_builder.set_ttl(&1000.into());
        tx_builder.set_fee(&to_bignum(1_000));

        let mut auxiliary_data = AuxiliaryData::new();
        let mut pubkey_native_scripts = NativeScripts::new();
        let mut oneof_native_scripts = NativeScripts::new();

        let spending_hash = spend.to_raw_key().hash();
        pubkey_native_scripts.add(&NativeScript::new_script_pubkey(&ScriptPubkey::new(
            &spending_hash,
        )));
        oneof_native_scripts.add(&NativeScript::new_script_n_of_k(&ScriptNOfK::new(
            1,
            &pubkey_native_scripts,
        )));
        auxiliary_data.set_native_scripts(&oneof_native_scripts);
        tx_builder.set_auxiliary_data(&auxiliary_data);

        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            1
        );
        assert_eq!(
            tx_builder
                .get_explicit_input()
                .unwrap()
                .checked_add(&tx_builder.get_implicit_input().unwrap())
                .unwrap(),
            tx_builder
                .get_explicit_output()
                .unwrap()
                .checked_add(&Value::new(&tx_builder.get_fee_if_set().unwrap()))
                .unwrap()
        );

        let _final_tx = tx_builder.build().unwrap();
        let _deser_t = TransactionBody::from_bytes(_final_tx.to_bytes()).unwrap();

        assert_eq!(_deser_t.to_bytes(), _final_tx.to_bytes());
        assert_eq!(
            _deser_t.auxiliary_data_hash.unwrap(),
            utils::hash_auxiliary_data(&auxiliary_data)
        );
    }

    #[test]
    fn build_tx_multisig_1on1_signed() {
        let mut tx_builder = create_tx_builder_with_fee(&create_linear_fee(10, 2));
        let spend = root_key_15()
            .derive(harden(1854)) //multisig
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1854)) //multisig
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();

        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw_key().hash());
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw_key().hash());
        let addr_net_0 = BaseAddress::new(
            NetworkInfo::testnet().network_id(),
            &spend_cred,
            &stake_cred,
        )
        .to_address();
        tx_builder.add_key_input(
            &spend.to_raw_key().hash(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(1_000_000)),
        );
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&addr_net_0)
                    .next()
                    .unwrap()
                    .with_coin(&to_bignum(999_000))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        tx_builder.set_ttl(&1000.into());
        tx_builder.set_fee(&to_bignum(1_000));

        let mut auxiliary_data = AuxiliaryData::new();
        let mut pubkey_native_scripts = NativeScripts::new();
        let mut oneof_native_scripts = NativeScripts::new();

        let spending_hash = spend.to_raw_key().hash();
        pubkey_native_scripts.add(&NativeScript::new_script_pubkey(&ScriptPubkey::new(
            &spending_hash,
        )));
        oneof_native_scripts.add(&NativeScript::new_script_n_of_k(&ScriptNOfK::new(
            1,
            &pubkey_native_scripts,
        )));
        auxiliary_data.set_native_scripts(&oneof_native_scripts);
        tx_builder.set_auxiliary_data(&auxiliary_data);

        let body = tx_builder.build().unwrap();

        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            1
        );
        assert_eq!(
            tx_builder
                .get_explicit_input()
                .unwrap()
                .checked_add(&tx_builder.get_implicit_input().unwrap())
                .unwrap(),
            tx_builder
                .get_explicit_output()
                .unwrap()
                .checked_add(&Value::new(&tx_builder.get_fee_if_set().unwrap()))
                .unwrap()
        );

        let mut witness_set = TransactionWitnessSet::new();
        let mut vkw = Vkeywitnesses::new();
        vkw.add(&make_vkey_witness(
            &hash_transaction(&body),
            &PrivateKey::from_normal_bytes(
                &hex::decode("c660e50315d76a53d80732efda7630cae8885dfb85c46378684b3c6103e1284a")
                    .unwrap(),
            )
            .unwrap(),
        ));
        witness_set.set_vkeys(&vkw);

        let _final_tx = build_full_tx(&body, &witness_set, None);
        let _deser_t = Transaction::from_bytes(_final_tx.to_bytes()).unwrap();
        assert_eq!(_deser_t.to_bytes(), _final_tx.to_bytes());
        assert_eq!(
            _deser_t.body().auxiliary_data_hash.unwrap(),
            utils::hash_auxiliary_data(&auxiliary_data)
        );
    }

    #[test]
    fn add_change_splits_change_into_multiple_outputs_when_nfts_overflow_output_size() {
        let linear_fee = LinearFee::new(&to_bignum(0), &to_bignum(1));
        let max_value_size = 100; // super low max output size to test with fewer assets
        let mut tx_builder = TransactionBuilder::new(
            &TransactionBuilderConfigBuilder::new()
                .fee_algo(&linear_fee)
                .pool_deposit(&to_bignum(0))
                .key_deposit(&to_bignum(0))
                .max_value_size(max_value_size)
                .max_tx_size(MAX_TX_SIZE)
                .coins_per_utxo_word(&to_bignum(1))
                .ex_unit_prices(&ExUnitPrices::from_float(0.0, 0.0))
                .prefer_pure_change(true)
                .build()
                .unwrap(),
        );

        let policy_id = PolicyID::from([0u8; 28]);
        let names = [
            AssetName::new(vec![99u8; 32]).unwrap(),
            AssetName::new(vec![0u8, 1, 2, 3]).unwrap(),
            AssetName::new(vec![4u8, 5, 6, 7]).unwrap(),
            AssetName::new(vec![5u8, 5, 6, 7]).unwrap(),
            AssetName::new(vec![6u8, 5, 6, 7]).unwrap(),
        ];
        let assets = names.iter().fold(Assets::new(), |mut a, name| {
            a.insert(&name, &to_bignum(500));
            a
        });
        let mut multiasset = MultiAsset::new();
        multiasset.insert(&policy_id, &assets);

        let mut input_value = Value::new(&to_bignum(300));
        input_value.set_multiasset(&multiasset);

        tx_builder.add_input(
            &ByronAddress::from_base58(
                "Ae2tdPwUPEZ5uzkzh1o2DHECiUi3iugvnnKHRisPgRRP3CTF4KCMvy54Xd3",
            )
            .unwrap()
            .to_address(),
            &TransactionInput::new(&genesis_id(), &0.into()),
            &input_value,
            None,
        );

        let output_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZD9QQf2ZrcYV34pYJwxK4vqXaF8EXkup1eYH73zUScHReM42b",
        )
        .unwrap()
        .to_address();
        let output_amount = Value::new(&to_bignum(50));

        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&output_addr)
                    .next()
                    .unwrap()
                    .with_value(&output_amount)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let change_addr = ByronAddress::from_base58(
            "Ae2tdPwUPEZGUEsuMAhvDcy94LKsZxDjCbgaiBBMgYpR8sKf96xJmit7Eho",
        )
        .unwrap()
        .to_address();

        let add_change_result = tx_builder.add_change_if_needed(&change_addr);
        assert!(add_change_result.is_ok());
        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            4
        );

        let total_outputs = tx_builder
            .outputs
            .0
            .iter()
            .chain(tx_builder.change_outputs.0.iter())
            .collect_vec();

        let change1 = total_outputs.get(1).unwrap().clone();
        let change2 = total_outputs.get(2).unwrap().clone();
        let change3 = total_outputs.get(3).unwrap().clone();

        assert_eq!(change1.address, change_addr);
        assert_eq!(change1.address, change2.address);
        assert_eq!(change1.address, change3.address);

        assert_eq!(change1.amount.coin, to_bignum(45));
        assert_eq!(change2.amount.coin, to_bignum(42));
        assert_eq!(change3.amount.coin, to_bignum(162));

        assert!(change1.amount.multiasset.is_some());
        assert!(change2.amount.multiasset.is_some());
        assert!(change3.amount.multiasset.is_none()); // purified

        let masset1 = change1.amount.multiasset.clone().unwrap();
        let masset2 = change2.amount.multiasset.clone().unwrap();

        assert_eq!(masset1.keys().len(), 1);
        assert_eq!(masset1.keys(), masset2.keys());

        let asset1 = masset1.get(&policy_id).unwrap();
        let asset2 = masset2.get(&policy_id).unwrap();
        assert_eq!(asset1.len(), 4);
        assert_eq!(asset2.len(), 1);

        names.iter().for_each(|name| {
            let v1 = asset1.get(name);
            let v2 = asset2.get(name);
            assert_ne!(v1.is_some(), v2.is_some());
            assert_eq!(v1.or(v2).unwrap(), to_bignum(500));
        });
    }

    fn create_json_metadatum_string() -> String {
        String::from("{ \"qwe\": 123 }")
    }

    fn create_json_metadatum() -> TransactionMetadatum {
        encode_json_str_to_metadatum(
            create_json_metadatum_string(),
            MetadataJsonSchema::NoConversions,
        )
        .unwrap()
    }

    fn create_aux_with_metadata(metadatum_key: &TransactionMetadatumLabel) -> AuxiliaryData {
        let mut metadata = GeneralTransactionMetadata::new();
        metadata.insert(metadatum_key, &create_json_metadatum());

        let mut aux = AuxiliaryData::new();
        aux.set_metadata(&metadata);

        let mut nats = NativeScripts::new();
        nats.add(&NativeScript::new_timelock_start(&TimelockStart::new(
            &123.into(),
        )));
        aux.set_native_scripts(&nats);

        return aux;
    }

    fn assert_json_metadatum(dat: &TransactionMetadatum) {
        let map = dat.as_map().unwrap();
        assert_eq!(map.len(), 1);
        let key = TransactionMetadatum::new_text(String::from("qwe")).unwrap();
        let val = map.get(&key).unwrap();
        assert_eq!(val.as_int().unwrap(), Int::new_i32(123));
    }

    #[test]
    fn set_metadata_with_empty_auxiliary() {
        let mut tx_builder = create_default_tx_builder();

        let num = to_bignum(42);
        tx_builder.set_metadata(&create_aux_with_metadata(&num).metadata().unwrap());

        assert!(tx_builder.auxiliary_data.is_some());

        let aux = tx_builder.auxiliary_data.unwrap();
        assert!(aux.metadata().is_some());
        assert!(aux.native_scripts().is_none());
        assert!(aux.plutus_scripts().is_none());

        let met = aux.metadata().unwrap();

        assert_eq!(met.len(), 1);
        assert_json_metadatum(&met.get(&num).unwrap());
    }

    #[test]
    fn set_metadata_with_existing_auxiliary() {
        let mut tx_builder = create_default_tx_builder();

        let num1 = to_bignum(42);
        tx_builder.set_auxiliary_data(&create_aux_with_metadata(&num1));

        let num2 = to_bignum(84);
        tx_builder.set_metadata(&create_aux_with_metadata(&num2).metadata().unwrap());

        let aux = tx_builder.auxiliary_data.unwrap();
        assert!(aux.metadata().is_some());
        assert!(aux.native_scripts().is_some());
        assert!(aux.plutus_scripts().is_none());

        let met = aux.metadata().unwrap();
        assert_eq!(met.len(), 1);
        assert!(met.get(&num1).is_none());
        assert_json_metadatum(&met.get(&num2).unwrap());
    }

    #[test]
    fn add_metadatum_with_empty_auxiliary() {
        let mut tx_builder = create_default_tx_builder();

        let num = to_bignum(42);
        tx_builder.add_metadatum(&num, &create_json_metadatum());

        assert!(tx_builder.auxiliary_data.is_some());

        let aux = tx_builder.auxiliary_data.unwrap();
        assert!(aux.metadata().is_some());
        assert!(aux.native_scripts().is_none());
        assert!(aux.plutus_scripts().is_none());

        let met = aux.metadata().unwrap();

        assert_eq!(met.len(), 1);
        assert_json_metadatum(&met.get(&num).unwrap());
    }

    #[test]
    fn add_metadatum_with_existing_auxiliary() {
        let mut tx_builder = create_default_tx_builder();

        let num1 = to_bignum(42);
        tx_builder.set_auxiliary_data(&create_aux_with_metadata(&num1));

        let num2 = to_bignum(84);
        tx_builder.add_metadatum(&num2, &create_json_metadatum());

        let aux = tx_builder.auxiliary_data.unwrap();
        assert!(aux.metadata().is_some());
        assert!(aux.native_scripts().is_some());
        assert!(aux.plutus_scripts().is_none());

        let met = aux.metadata().unwrap();
        assert_eq!(met.len(), 2);
        assert_json_metadatum(&met.get(&num1).unwrap());
        assert_json_metadatum(&met.get(&num2).unwrap());
    }

    #[test]
    fn add_json_metadatum_with_empty_auxiliary() {
        let mut tx_builder = create_default_tx_builder();

        let num = to_bignum(42);
        tx_builder
            .add_json_metadatum(&num, create_json_metadatum_string())
            .unwrap();

        assert!(tx_builder.auxiliary_data.is_some());

        let aux = tx_builder.auxiliary_data.unwrap();
        assert!(aux.metadata().is_some());
        assert!(aux.native_scripts().is_none());
        assert!(aux.plutus_scripts().is_none());

        let met = aux.metadata().unwrap();

        assert_eq!(met.len(), 1);
        assert_json_metadatum(&met.get(&num).unwrap());
    }

    #[test]
    fn add_json_metadatum_with_existing_auxiliary() {
        let mut tx_builder = create_default_tx_builder();

        let num1 = to_bignum(42);
        tx_builder.set_auxiliary_data(&create_aux_with_metadata(&num1));

        let num2 = to_bignum(84);
        tx_builder
            .add_json_metadatum(&num2, create_json_metadatum_string())
            .unwrap();

        let aux = tx_builder.auxiliary_data.unwrap();
        assert!(aux.metadata().is_some());
        assert!(aux.native_scripts().is_some());
        assert!(aux.plutus_scripts().is_none());

        let met = aux.metadata().unwrap();
        assert_eq!(met.len(), 2);
        assert_json_metadatum(&met.get(&num1).unwrap());
        assert_json_metadatum(&met.get(&num2).unwrap());
    }

    fn create_asset_name() -> AssetName {
        AssetName::new(vec![0u8, 1, 2, 3]).unwrap()
    }

    fn create_mint_asset() -> MintAssets {
        MintAssets::new_from_entry(&create_asset_name(), Int::new_i32(1234))
    }

    fn create_assets() -> Assets {
        let mut assets = Assets::new();
        assets.insert(&create_asset_name(), &to_bignum(1234));
        return assets;
    }

    fn create_mint_with_one_asset(policy_id: &PolicyID) -> Mint {
        Mint::new_from_entry(policy_id, &create_mint_asset())
    }

    fn create_multiasset_one_asset(policy_id: &PolicyID) -> MultiAsset {
        let mut mint = MultiAsset::new();
        mint.insert(policy_id, &create_assets());
        return mint;
    }

    fn assert_mint_asset(mint: &Mint, policy_id: &PolicyID) {
        assert!(mint.get(&policy_id).is_some());
        let result_asset = mint.get(&policy_id).unwrap();
        assert_eq!(result_asset.len(), 1);
        assert_eq!(
            result_asset.get(&create_asset_name()).unwrap(),
            Int::new_i32(1234)
        );
    }

    fn mint_script_and_policy_and_hash(x: u8) -> (NativeScript, PolicyID, Ed25519KeyHash) {
        let hash = fake_key_hash(x);
        let mint_script = NativeScript::new_script_pubkey(&ScriptPubkey::new(&hash));
        let policy_id = mint_script.hash(ScriptHashNamespace::NativeScript);
        (mint_script, policy_id, hash)
    }

    fn mint_script_and_policy(x: u8) -> (NativeScript, PolicyID) {
        let (m, p, _) = mint_script_and_policy_and_hash(x);
        (m, p)
    }

    #[test]
    fn set_mint_asset_with_empty_mint() {
        let mut tx_builder = create_default_tx_builder();

        let (mint_script, policy_id) = mint_script_and_policy(0);
        tx_builder.add_mint(
            &policy_id,
            &create_mint_asset(),
            Some(ScriptWitness::new_native_witness(&mint_script)),
        );

        assert!(tx_builder.mint.is_some());
        assert!(tx_builder.native_scripts.is_some());

        let mint = tx_builder.mint().unwrap();
        let mint_scripts = tx_builder.native_scripts.unwrap();

        assert_eq!(mint.len(), 1);
        assert_mint_asset(&mint, &policy_id);

        assert_eq!(mint_scripts.len(), 1);
        assert_eq!(mint_scripts.get(0), mint_script);
    }

    #[test]
    #[ignore]
    fn set_mint_asset_with_existing_mint() {
        // let mut tx_builder = create_default_tx_builder();

        // let (mint_script1, policy_id1) = mint_script_and_policy(0);
        // let (mint_script2, policy_id2) = mint_script_and_policy(1);

        // tx_builder
        //     .set_mint(
        //         &create_mint_with_one_asset(&policy_id1),
        //         &NativeScripts::from(vec![mint_script1.clone()]),
        //     )
        //     .unwrap();

        // tx_builder.set_mint_asset(&mint_script2, &create_mint_asset());

        // assert!(tx_builder.mint.is_some());
        // assert!(tx_builder.native_scripts.is_some());

        // let mint = tx_builder.mint.unwrap();
        // let mint_scripts = tx_builder.native_scripts.unwrap();

        // assert_eq!(mint.len(), 2);
        // assert_mint_asset(&mint, &policy_id1);
        // assert_mint_asset(&mint, &policy_id2);

        // // Only second script is present in the scripts
        // assert_eq!(mint_scripts.len(), 2);
        // assert_eq!(mint_scripts.get(0), mint_script1);
        // assert_eq!(mint_scripts.get(1), mint_script2);
    }

    #[test]
    fn add_mint_asset_with_empty_mint() {
        let mut tx_builder = create_default_tx_builder();

        let (mint_script, policy_id) = mint_script_and_policy(0);

        tx_builder.add_mint(
            &policy_id,
            &MintAssets::new_from_entry(&create_asset_name(), Int::new_i32(1234)),
            Some(ScriptWitness::new_native_witness(&mint_script)),
        );

        assert!(tx_builder.mint.is_some());
        assert!(tx_builder.native_scripts.is_some());

        let mint = tx_builder.mint().unwrap();
        let mint_scripts = tx_builder.native_scripts.unwrap();

        assert_eq!(mint.len(), 1);
        assert_mint_asset(&mint, &policy_id);

        assert_eq!(mint_scripts.len(), 1);
        assert_eq!(mint_scripts.get(0), mint_script);
    }

    #[test]
    #[ignore]
    fn add_mint_asset_with_existing_mint() {
        // let mut tx_builder = create_default_tx_builder();

        // let (mint_script1, policy_id1) = mint_script_and_policy(0);
        // let (mint_script2, policy_id2) = mint_script_and_policy(1);

        // tx_builder
        //     .set_mint(
        //         &create_mint_with_one_asset(&policy_id1),
        //         &NativeScripts::from(vec![mint_script1.clone()]),
        //     )
        //     .unwrap();
        // tx_builder.add_mint_asset(&mint_script2, &create_asset_name(), Int::new_i32(1234));

        // assert!(tx_builder.mint.is_some());
        // assert!(tx_builder.native_scripts.is_some());

        // let mint = tx_builder.mint.unwrap();
        // let mint_scripts = tx_builder.native_scripts.unwrap();

        // assert_eq!(mint.len(), 2);
        // assert_mint_asset(&mint, &policy_id1);
        // assert_mint_asset(&mint, &policy_id2);

        // assert_eq!(mint_scripts.len(), 2);
        // assert_eq!(mint_scripts.get(0), mint_script1);
        // assert_eq!(mint_scripts.get(1), mint_script2);
    }

    #[test]
    fn add_output_amount() {
        let mut tx_builder = create_default_tx_builder();

        let policy_id1 = PolicyID::from([0u8; 28]);
        let multiasset = create_multiasset_one_asset(&policy_id1);
        let mut value = Value::new(&to_bignum(42));
        value.set_multiasset(&multiasset);

        let address = byron_address();
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&address)
                    .next()
                    .unwrap()
                    .with_value(&value)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            1
        );
        let out = tx_builder.outputs.get(0);

        assert_eq!(out.address.to_bytes(), address.to_bytes());
        assert_eq!(out.amount, value);
    }

    #[test]
    fn add_output_coin() {
        let mut tx_builder = create_default_tx_builder();

        let address = byron_address();
        let coin = to_bignum(43);
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&address)
                    .next()
                    .unwrap()
                    .with_coin(&coin)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            1
        );
        let out = tx_builder.outputs.get(0);

        assert_eq!(out.address.to_bytes(), address.to_bytes());
        assert_eq!(out.amount.coin, coin);
        assert!(out.amount.multiasset.is_none());
    }

    #[test]
    fn add_output_coin_and_multiasset() {
        let mut tx_builder = create_default_tx_builder();

        let policy_id1 = PolicyID::from([0u8; 28]);
        let multiasset = create_multiasset_one_asset(&policy_id1);

        let address = byron_address();
        let coin = to_bignum(42);

        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&address)
                    .next()
                    .unwrap()
                    .with_coin_and_asset(&coin, &multiasset)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            1
        );
        let out = tx_builder.outputs.get(0);

        assert_eq!(out.address.to_bytes(), address.to_bytes());
        assert_eq!(out.amount.coin, coin);
        assert_eq!(out.amount.multiasset.unwrap(), multiasset);
    }

    #[test]
    fn add_output_asset_and_min_required_coin() {
        let mut tx_builder = create_reallistic_tx_builder();

        let policy_id1 = PolicyID::from([0u8; 28]);
        let multiasset = create_multiasset_one_asset(&policy_id1);

        let address = byron_address();
        tx_builder
            .add_output(
                &TransactionOutputBuilder::new()
                    .with_address(&address)
                    .next()
                    .unwrap()
                    .with_asset_and_min_required_coin(
                        &multiasset,
                        &tx_builder.config.coins_per_utxo_word,
                    )
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .unwrap();

        assert_eq!(
            tx_builder
                .outputs
                .0
                .iter()
                .chain(tx_builder.change_outputs.0.iter())
                .collect_vec()
                .len(),
            1
        );
        let out = tx_builder.outputs.get(0);

        assert_eq!(out.address.to_bytes(), address.to_bytes());
        assert_eq!(out.amount.multiasset.unwrap(), multiasset);
        assert_eq!(out.amount.coin, to_bignum(1344798));
    }

    #[test]
    fn add_mint_includes_witnesses_into_fee_estimation() {
        let mut tx_builder = create_reallistic_tx_builder();

        let hash0 = fake_key_hash(0);

        let (mint_script1, _, hash1) = mint_script_and_policy_and_hash(1);
        let (mint_script2, _, _) = mint_script_and_policy_and_hash(2);
        let (mint_script3, _, _) = mint_script_and_policy_and_hash(3);

        let name1 = AssetName::new(vec![0u8, 1, 2, 3]).unwrap();
        let name2 = AssetName::new(vec![1u8, 1, 2, 3]).unwrap();
        let name3 = AssetName::new(vec![2u8, 1, 2, 3]).unwrap();
        let name4 = AssetName::new(vec![3u8, 1, 2, 3]).unwrap();
        let amount = Int::new_i32(1234);

        // One input from unrelated address
        tx_builder.add_key_input(
            &hash0,
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(10_000_000)),
        );

        // One input from same address as mint
        tx_builder.add_key_input(
            &hash1,
            &TransactionInput::new(&genesis_id(), &0.into()),
            &Value::new(&to_bignum(10_000_000)),
        );

        // Original tx fee now assumes two VKey signatures for two inputs
        let original_tx_fee = tx_builder.min_fee().unwrap();
        assert_eq!(original_tx_fee, to_bignum(168361));

        // Add minting four assets from three different policies

        tx_builder.add_mint(
            &hash_script(ScriptHashNamespace::NativeScript, mint_script1.to_bytes()),
            &MintAssets::new_from_entry(&name1, amount.clone()),
            Some(ScriptWitness::new_native_witness(&mint_script1)),
        );
        tx_builder.add_mint(
            &hash_script(ScriptHashNamespace::NativeScript, mint_script2.to_bytes()),
            &MintAssets::new_from_entry(&name2, amount.clone()),
            Some(ScriptWitness::new_native_witness(&mint_script2)),
        );
        tx_builder.add_mint(
            &hash_script(ScriptHashNamespace::NativeScript, mint_script3.to_bytes()),
            &MintAssets::new_from_entry(&name3, amount.clone()),
            Some(ScriptWitness::new_native_witness(&mint_script3)),
        );
        tx_builder.add_mint(
            &hash_script(ScriptHashNamespace::NativeScript, mint_script3.to_bytes()),
            &MintAssets::new_from_entry(&name4, amount.clone()),
            Some(ScriptWitness::new_native_witness(&mint_script3)),
        );

        let mint = tx_builder.mint().unwrap();
        let mint_len = mint.to_bytes().len();

        let mint_scripts = tx_builder.get_witness_set();
        let mint_scripts_len =
            mint_scripts.to_bytes().len() - TransactionWitnessSet::new().to_bytes().len();

        let fee_coefficient = tx_builder.config.fee_algo.coefficient();

        let raw_mint_fee = fee_coefficient
            .checked_mul(&to_bignum(mint_len as u64))
            .unwrap();

        let raw_mint_script_fee = fee_coefficient
            .checked_mul(&to_bignum(mint_scripts_len as u64))
            .unwrap();

        assert_eq!(raw_mint_fee, to_bignum(5544));
        assert_eq!(raw_mint_script_fee, to_bignum(4312));

        let new_tx_fee = tx_builder.min_fee().unwrap();

        let fee_diff_from_adding_mint = new_tx_fee.checked_sub(&original_tx_fee).unwrap();

        let witness_fee_increase = fee_diff_from_adding_mint
            .checked_sub(&raw_mint_fee)
            .unwrap()
            .checked_sub(&raw_mint_script_fee)
            .unwrap();

        assert_eq!(witness_fee_increase, to_bignum(8932));

        let fee_increase_bytes = from_bignum(&witness_fee_increase)
            .checked_div(from_bignum(&fee_coefficient))
            .unwrap();

        // Two vkey witnesses 96 bytes each (32 byte pubkey + 64 byte signature)
        // Plus 11 bytes overhead for CBOR wrappers
        // This is happening because we have three different minting policies
        // but the same key-hash from one of them is already also used in inputs
        // so no suplicate witness signature is require for that one
        assert_eq!(fee_increase_bytes, 203);
    }

    #[test]
    #[ignore]
    fn fee_estimation_fails_on_missing_mint_scripts() {
        // let mut tx_builder = create_reallistic_tx_builder();

        // // No error estimating fee without mint
        // assert!(tx_builder.min_fee().is_ok());

        // let (mint_script1, policy_id1) = mint_script_and_policy(0);
        // let (mint_script2, _) = mint_script_and_policy(1);

        // let name1 = AssetName::new(vec![0u8, 1, 2, 3]).unwrap();
        // let amount = Int::new_i32(1234);

        // let mut mint = Mint::new();
        // mint.insert(
        //     &policy_id1,
        //     &MintAssets::new_from_entry(&name1, amount.clone()),
        // );

        // tx_builder
        //     .set_mint(&mint, &NativeScripts::from(vec![mint_script1]))
        //     .unwrap();

        // let est1 = tx_builder.min_fee();
        // assert!(est1.is_ok());

        // tx_builder.add_mint_asset(&mint_script2, &name1, amount.clone());

        // let est2 = tx_builder.min_fee();
        // assert!(est2.is_ok());

        // Native script assertion has been commented out in `.min_fee`
        // Until implemented in a more performant manner
        // TODO: these test parts might be returned back when it's done

        // // Remove one mint script
        // tx_builder.native_scripts =
        //     Some(NativeScripts::from(vec![tx_builder.native_scripts.unwrap().get(1)]));
        //
        // // Now two different policies are minted but only one witness script is present
        // let est3 = tx_builder.min_fee();
        // assert!(est3.is_err());
        // assert!(est3.err().unwrap().to_string().contains(&format!("{:?}", hex::encode(policy_id1.to_bytes()))));
        //
        // // Remove all mint scripts
        // tx_builder.native_scripts = Some(NativeScripts::new());
        //
        // // Mint exists but no witness scripts at all present
        // let est4 = tx_builder.min_fee();
        // assert!(est4.is_err());
        // assert!(est4.err().unwrap().to_string().contains("witness scripts are not provided"));
        //
        // // Remove all mint scripts
        // tx_builder.native_scripts = None;
        //
        // // Mint exists but no witness scripts at all present
        // let est5 = tx_builder.min_fee();
        // assert!(est5.is_err());
        // assert!(est5.err().unwrap().to_string().contains("witness scripts are not provided"));
    }

    #[test]
    fn total_input_with_mint_and_burn() {
        let mut tx_builder = create_tx_builder_with_fee(&create_linear_fee(0, 1));
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();

        let (mint_script1, policy_id1) = mint_script_and_policy(0);
        let (mint_script2, policy_id2) = mint_script_and_policy(1);

        let name = AssetName::new(vec![0u8, 1, 2, 3]).unwrap();

        let ma_input1 = 100;
        let ma_input2 = 200;
        let ma_output1 = 60;

        let multiassets = [ma_input1, ma_input2, ma_output1]
            .iter()
            .map(|input| {
                let mut multiasset = MultiAsset::new();
                multiasset.insert(&policy_id1, &{
                    let mut assets = Assets::new();
                    assets.insert(&name, &to_bignum(*input));
                    assets
                });
                multiasset.insert(&policy_id2, &{
                    let mut assets = Assets::new();
                    assets.insert(&name, &to_bignum(*input));
                    assets
                });
                multiasset
            })
            .collect::<Vec<MultiAsset>>();

        for (multiasset, ada) in multiassets
            .iter()
            .zip([100u64, 100, 100].iter().cloned().map(to_bignum))
        {
            let mut input_amount = Value::new(&ada);
            input_amount.set_multiasset(multiasset);

            tx_builder.add_key_input(
                &&spend.to_raw_key().hash(),
                &TransactionInput::new(&genesis_id(), &0.into()),
                &input_amount,
            );
        }

        let total_input_before_mint = tx_builder.get_total_input().unwrap();

        assert_eq!(total_input_before_mint.coin, to_bignum(300));
        let ma1 = total_input_before_mint.multiasset.unwrap();
        assert_eq!(
            ma1.get(&policy_id1).unwrap().get(&name).unwrap(),
            to_bignum(360)
        );
        assert_eq!(
            ma1.get(&policy_id2).unwrap().get(&name).unwrap(),
            to_bignum(360)
        );

        tx_builder.add_mint(
            &hash_script(ScriptHashNamespace::NativeScript, mint_script1.to_bytes()),
            &MintAssets::new_from_entry(&name, Int::new_i32(40)),
            Some(ScriptWitness::new_native_witness(&mint_script1)),
        );
        tx_builder.add_mint(
            &hash_script(ScriptHashNamespace::NativeScript, mint_script2.to_bytes()),
            &MintAssets::new_from_entry(&name, Int::new_i32(-40)),
            Some(ScriptWitness::new_native_witness(&mint_script2)),
        );

        let total_input_after_mint = tx_builder.get_total_input().unwrap();

        assert_eq!(total_input_after_mint.coin, to_bignum(300));
        let ma2 = total_input_after_mint.multiasset.unwrap();
        assert_eq!(
            ma2.get(&policy_id1).unwrap().get(&name).unwrap(),
            to_bignum(400)
        );
        assert_eq!(
            ma2.get(&policy_id2).unwrap().get(&name).unwrap(),
            to_bignum(320)
        );
    }
}
