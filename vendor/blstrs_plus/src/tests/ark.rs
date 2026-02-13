use crate::{G1Projective, G2Projective, Scalar};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};
use elliptic_curve::hash2curve::ExpandMsgXmd;
use ff::Field;

#[test]
fn cold_register() {
    let dk1 = Scalar::random(&mut rand::rngs::OsRng);
    let dk2 = Scalar::random(&mut rand::rngs::OsRng);
    let ek1 = G2Projective::GENERATOR * dk1;
    let ek2 = G2Projective::GENERATOR * dk2;

    let before = std::time::Instant::now();
    let r1 = Scalar::random(&mut rand::rngs::OsRng);
    let r2 = Scalar::random(&mut rand::rngs::OsRng);
    let a1 = G2Projective::GENERATOR * r1;
    let a2 = G2Projective::GENERATOR * r2;
    let mut bytes = [0u8; 192 + 8];
    bytes[..96].copy_from_slice(a1.to_compressed().as_ref());
    bytes[96..192].copy_from_slice(a2.to_compressed().as_ref());
    bytes[192..].copy_from_slice(&1000u64.to_be_bytes());
    let c = Scalar::hash::<ExpandMsgXmd<sha2::Sha256>>(&bytes, b"BLS12381_XMD:SHA-256_RO_NUL_");
    let z1 = r1 + c * dk1;
    let z2 = r2 + c * dk2;
    println!("cold_proof_gen: {:?}", before.elapsed());
    let before = std::time::Instant::now();
    let lhs1 = G2Projective::GENERATOR * z1;
    let rhs1 = a1 + ek1 * c;
    let lhs2 = G2Projective::GENERATOR * z2;
    let rhs2 = a2 + ek2 * c;
    assert_eq!(lhs1, rhs1);
    assert_eq!(lhs2, rhs2);
    println!("cold_proof_verify: {:?}", before.elapsed());
}

#[test]
fn fft() {
    const THRESHOLD: usize = 67;
    let tau = Scalar::random(&mut rand::rngs::OsRng);
    let mut t_poly_coeffs = vec![tau; THRESHOLD];
    for i in 1..THRESHOLD {
        t_poly_coeffs[i] = t_poly_coeffs[i - 1] * tau;
    }
    let t_poly = DensePolynomial::<Scalar>::from_coefficients_slice(&t_poly_coeffs);
    let poly = DensePolynomial::<Scalar>::rand(THRESHOLD, &mut rand::thread_rng());

    let domain = GeneralEvaluationDomain::<Scalar>::new(128).unwrap();
    let aux_domain = GeneralEvaluationDomain::<Scalar>::new(256).unwrap();

    let t_evals = aux_domain.fft(t_poly.coeffs());

    let before = std::time::Instant::now();
    let d_evals = aux_domain.fft(poly.coeffs());

    let dt_evals = t_evals
        .iter()
        .zip(d_evals.iter())
        .map(|(t, d)| G1Projective::GENERATOR * t * d)
        .collect::<Vec<_>>();

    let dt_poly = aux_domain.ifft(&dt_evals);
    let actual = domain.fft(&dt_poly[domain.size()..]);
    println!("fft: {:?}", before.elapsed());
    assert_eq!(actual.len(), 128);

    // let srs = t_poly_coeffs.iter().map(|t| G1Projective::GENERATOR * *t).collect::<Vec<_>>();
    // let expected = commit_in_each_omega_i(&srs, &domain, &poly);
    // assert_eq!(actual, expected);
}

fn commit(srs: &[G1Projective], poly: &DensePolynomial<Scalar>) -> G1Projective {
    let coeff_scalars = poly.coeffs.iter().map(|c| *c).collect::<Vec<_>>();
    G1Projective::sum_of_products(&srs[..], &coeff_scalars)
}

fn open(
    srs: &[G1Projective],
    poly: &DensePolynomial<Scalar>,
    challenge: Scalar,
) -> (Scalar, G1Projective) {
    let q = poly / &DensePolynomial::from_coefficients_slice(&[-challenge, Scalar::ONE]);
    let proof = commit(srs, &q);
    (poly.evaluate(&challenge), proof)
}

fn commit_in_each_omega_i(
    srs: &[G1Projective],
    domain: &GeneralEvaluationDomain<Scalar>,
    poly: &DensePolynomial<Scalar>,
) -> Vec<G1Projective> {
    domain
        .elements()
        .map(|omega_pow_i| open(srs, poly, omega_pow_i).1)
        .collect()
}
