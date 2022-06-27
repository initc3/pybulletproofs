extern crate rand;
extern crate curve25519_dalek_ng;
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::constants::BASEPOINT_ORDER;
extern crate merlin;
use merlin::Transcript;
extern crate bulletproofs;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use pyo3::prelude::*;

/// Given `data` with `len >= 32`, return the first 32 bytes.
pub fn read32(data: &[u8]) -> [u8; 32] {
    let mut buf32 = [0u8; 32];
    buf32[..].copy_from_slice(&data[..32]);
    buf32
}

// What will happen if we have more than 2^64 servers? Although it is extremely impossible, can
// adversarry exploit this?
pub fn lagrange_coefficient(covariate_u64: u64, others_u64: Vec<u64>) -> PyResult<Scalar> {
    let covariate = Scalar::from(covariate_u64);
    let others: Vec<_> = others_u64
        .iter()
        .map(|v| Scalar::from(*v))
        .collect();

    let denominator_factors: Vec<_> = others
        .iter()
        .map(|v| covariate - v)
        .collect();
    let numerator_factors: Vec<_> = others
        .iter()
        .map(|v| -v)
        .collect();
    
    let denominator = denominator_factors.iter().copied().reduce(|a, b| a * b).unwrap();
    let numerator = numerator_factors.iter().copied().reduce(|a, b| a * b).unwrap();

    let coefficient = numerator * denominator.invert();
    
    Ok(coefficient)
}

#[pyfunction]
fn get_ed25519_basepoint_order() -> PyResult<[u8; 32]> {
    Ok(BASEPOINT_ORDER.to_bytes())
}

#[pyfunction]
fn pedersen_commit(secret_value_bytes: [u8; 32], blinding_bytes: [u8; 32]) -> PyResult<[u8; 32]> {
    let secret_value = Scalar::from_bytes_mod_order(secret_value_bytes);
    let blinding = Scalar::from_bytes_mod_order(blinding_bytes);

    let pc_gens = PedersenGens::default();
    let commitment = pc_gens.commit(secret_value, blinding);

    Ok(commitment.compress().to_bytes())
}

#[pyfunction]
fn pedersen_open(secret_value: u64, blinding: u64, commitment_bytes: [u8; 32]) -> PyResult<bool> {
    let secret_value_scalar = Scalar::from(secret_value);
    let blinding_scalar = Scalar::from(blinding);
    let pc_gens = PedersenGens::default();
    let opened_commitment_bytes = pc_gens.commit(secret_value_scalar, blinding_scalar).compress().to_bytes();
    Ok(opened_commitment_bytes == commitment_bytes)
}


#[pyfunction]
fn pedersen_aggregate(commitment_bytes_list: Vec<[u8; 32]>, covariates: Vec<u64>) -> PyResult<[u8;32]> {
    let commitment_list: Vec<_> = commitment_bytes_list
        .iter()
        .map(|v| CompressedRistretto(read32(v)).decompress().unwrap())
        .collect();

    let scaled_commitment_list: Vec<_> = commitment_list
        .iter()
        .enumerate()
        .map(|(idx, v)| v * lagrange_coefficient(covariates[idx], [&covariates[..idx], &covariates[idx+1..]].concat()).unwrap())
        .collect();

    let commitment = scaled_commitment_list.iter().copied().reduce(|a, b| a + b).unwrap();
    // TODO: figure out if the list is in the correct order.
    // for commitment_bytes in commitment_bytes_list.iter() {
    //     commitment_list.push(CompressedRistretto(read32(commitment_bytes)).decompress());
    // }

    // TODO: take in a list of Pedersen commitment. Interpolate them.
    // TODO: upgrade to robust version.
    Ok(commitment.compress().to_bytes())
}

#[pyfunction]
fn pedersen_sum(commitment_bytes_list: Vec<[u8; 32]>) -> PyResult<[u8;32]> {
    let commitment_list: Vec<_> = commitment_bytes_list
        .iter()
        .map(|v| CompressedRistretto(read32(v)).decompress().unwrap())
        .collect();

    let commitment = commitment_list.iter().copied().reduce(|a, b| a + b).unwrap();
    Ok(commitment.compress().to_bytes())
}

#[pyfunction]
fn pedersen_subtract(commitment_bytes_a: [u8; 32], commitment_bytes_b: [u8; 32]) -> PyResult<[u8;32]> {
    let comm_a = CompressedRistretto(read32(&commitment_bytes_a)).decompress().unwrap();
    let comm_b = CompressedRistretto(read32(&commitment_bytes_b)).decompress().unwrap();

    let commitment = comm_a - comm_b;
    Ok(commitment.compress().to_bytes())
}

#[pyfunction]
fn pedersen_compare(recovered_commitment: [u8; 32], onchain_commitment: [u8; 32]) -> PyResult<bool> {
    Ok(recovered_commitment == onchain_commitment)
}

// TODO: return the blinding as bytes using as_bytes (returns &[u8; 32])
#[pyfunction]
fn zkrp_prove(secret_value: u64, bits: usize) -> PyResult<(Vec<u8>, [u8; 32], [u8; 32])> {
    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 1.
    let bp_gens = BulletproofGens::new(64, 1);

    // The API takes a blinding factor for the commitment.
    let blinding = Scalar::random(&mut rand::thread_rng());

    // The proof can be chained to an existing transcript.
    // Here we create a transcript with a doctest domain separator.
    let mut prover_transcript = Transcript::new(b"zkrp");

    // Create a 32-bit rangeproof.
    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &blinding,
        bits,
    ).expect("A real program could handle errors");

    Ok((proof.to_bytes(), committed_value.to_bytes(), blinding.to_bytes()))
}

#[pyfunction]
fn zkrp_prove_single(secret_value: u64, blinding_bytes: [u8; 32], bits: usize) -> PyResult<(Vec<u8>, [u8; 32], [u8; 32])> {
    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 1.
    let bp_gens = BulletproofGens::new(64, 1);

    // The API takes a blinding factor for the commitment.
    let blinding = Scalar::from_bytes_mod_order(blinding_bytes);

    // The proof can be chained to an existing transcript.
    // Here we create a transcript with a doctest domain separator.
    let mut prover_transcript = Transcript::new(b"zkrp");

    // Create a 32-bit rangeproof.
    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &blinding,
        bits,
    ).expect("A real program could handle errors");

    Ok((proof.to_bytes(), committed_value.to_bytes(), blinding_bytes))
}

#[pyfunction]
fn zkrp_prove_multiple(secret_values: Vec<u64>, blindings_bytes: Vec<[u8; 32]>, bits: usize) -> PyResult<(Vec<u8>, Vec<[u8; 32]>, Vec<[u8; 32]>)> {
    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to |commited_values|.
    let bp_gens = BulletproofGens::new(64, secret_values.len());

    // The API takes a blinding factor for the commitment.
    let blindings: Vec<Scalar> = blindings_bytes.iter()
    .map(|v| Scalar::from_bytes_mod_order(*v))
    .collect();

    // The proof can be chained to an existing transcript.
    // Here we create a transcript with a doctest domain separator.
    let mut prover_transcript = Transcript::new(b"zkrp");

    // Create a 32-bit rangeproof.
    let (proof, committed_values) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_values.as_slice(),
        &blindings,
        bits,
    ).expect("A real program could handle errors");

    let committed_values_bytes: Vec<_> = committed_values.iter()
    .map(|v| v.to_bytes())
    .collect();

    Ok((proof.to_bytes(), committed_values_bytes, blindings_bytes))
}

#[pyfunction]
fn zkrp_verify_single(proof_bytes: Vec<u8>, committed_value_bytes: [u8; 32], bits: usize) -> PyResult<bool> {
    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 1.
    let bp_gens = BulletproofGens::new(64, 1);

	let proof = RangeProof::from_bytes(proof_bytes.as_slice()).expect("Error: Proof deserialization failed!");
    let committed_value = CompressedRistretto(read32(&committed_value_bytes));
    // Verification requires a transcript with identical initial state:
    let mut verifier_transcript = Transcript::new(b"zkrp");
    Ok(proof.verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &committed_value, bits).is_ok())
}

#[pyfunction]
fn zkrp_verify_multiple(proof_bytes: Vec<u8>, committed_values_bytes: Vec<[u8; 32]>, bits: usize) -> PyResult<bool> {
    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to |commited_values|.
    let bp_gens = BulletproofGens::new(64, committed_values_bytes.len());

	let proof = RangeProof::from_bytes(proof_bytes.as_slice()).expect("Error: Proof deserialization failed!");
    let committed_values : Vec<CompressedRistretto> = committed_values_bytes.iter()
    .map(|v| CompressedRistretto(read32(v)))
    .collect();
    
    // Verification requires a transcript with identical initial state:
    let mut verifier_transcript = Transcript::new(b"zkrp");
    Ok(proof.verify_multiple(&bp_gens, &pc_gens, &mut verifier_transcript, &committed_values, bits).is_ok())
}

/// A Python module implemented in Rust.
#[pymodule]
fn pybulletproofs(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_ed25519_basepoint_order, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_commit, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_open, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_aggregate, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_sum, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_subtract, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_compare, m)?)?;
    m.add_function(wrap_pyfunction!(zkrp_prove, m)?)?;
    m.add_function(wrap_pyfunction!(zkrp_prove_single, m)?)?;
    m.add_function(wrap_pyfunction!(zkrp_prove_multiple, m)?)?;
    m.add_function(wrap_pyfunction!(zkrp_verify_single, m)?)?;
    m.add_function(wrap_pyfunction!(zkrp_verify_multiple, m)?)?;
    Ok(())
}
