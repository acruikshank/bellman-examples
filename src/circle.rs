#![allow(unused_imports)]
#![allow(unused_variables)]
extern crate bellman;
extern crate pairing;
extern crate rand;

// For randomness (during paramgen and proof generation)
use self::rand::{thread_rng, Rng};

// Bring in some tools for using pairing-friendly curves
use self::pairing::{
    Engine,
    Field,
    PrimeField
};

// We're going to use the BLS12-381 pairing-friendly elliptic curve.
use self::pairing::bls12_381::{
    Bls12,
    Fr
};

// We'll use these interfaces to construct our circuit.
use self::bellman::{
    Circuit,
    ConstraintSystem,
    SynthesisError
};

// We're going to use the Groth16 proving system.
use self::bellman::groth16::{
    Proof,
    generate_random_parameters,
    prepare_verifying_key,
    create_random_proof,
    verify_proof,
};

// proving that I know integer x and y such that (x, y) defines a point on a
// circle with radius given as a public variable
// Generalized: x^2 + y^2 == r^2
pub struct CircleDemo<E: Engine> {
    pub x: Option<E::Fr>,
    pub y: Option<E::Fr>,
    pub r: Option<E::Fr>,
}

impl <E: Engine> Circuit<E> for CircleDemo<E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self, 
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        // Flattened into quadratic equations (x^2 + y^2 == r^2): 
        // x * x = x_square
        // y * y = y_square
        // r * r = r_square
        // (x_square + y_square) * 1 = r_square
        // Resulting R1CS with w = [one, x, x_square, y, y_square, r, r_square]
        
        // Allocate the first private "auxiliary" variable
        let x_val = self.x;
        let x = cs.alloc(|| "x", || {
            x_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        // Allocate: x * x = x_square
        let x_square_val = x_val.map(|mut e| {
            e.square();
            e
        });
        let x_square = cs.alloc(|| "x_square", || {
            x_square_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // Enforce: x * x = x_square
        cs.enforce(
            || "x_square",
            |lc| lc + x,
            |lc| lc + x,
            |lc| lc + x_square
        );
        
        // Allocate the second private "auxiliary" variable
        let y_val = self.y;
        let y = cs.alloc(|| "y", || {
            y_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate: y * y = y_square
        let y_square_val = y_val.map(|mut e| {
            e.square();
            e
        });
        let y_square = cs.alloc(|| "y_square", || {
            y_square_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // Enforce: y * y = y_sqaure
        cs.enforce(
            || "y_square",
            |lc| lc + y,
            |lc| lc + y,
            |lc| lc + y_square
        );
        
        // Allocating r (a public input) uses alloc_input
        let r = cs.alloc_input(|| "r", || {
            self.r.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate: r * r = r_square
        let r_square_val = self.r.map(|mut e| {
            e.square();
            e
        });
        let r_square = cs.alloc(|| "r_square", || {
            r_square_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // Enforce: r * r = r_sqaure
        cs.enforce(
            || "r_square",
            |lc| lc + r,
            |lc| lc + r,
            |lc| lc + r_square
        );

        // x_square + y_sqaure = r_square
        // => (x_square + y_sqaure) * 1 = r_square
        cs.enforce(
            || "circle",
            |lc| lc + x_square + y_square,
            |lc| lc + CS::one(),
            |lc| lc + r_square
        );
        
        Ok(())
    }
}

#[test]
fn test_circle_proof(){
    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let rng = &mut thread_rng();
    
    println!("SETUP: Creating parameters...");
    
    // Create parameters for our circuit
    let params = {
        let c = CircleDemo::<Bls12> {
            x: None,
            y: None,
            r: None,
        };

        generate_random_parameters(c, rng).unwrap()
    };
    
    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    let public_radius = Fr::from_str("5");

    println!("Alice: Creating proofs...");
    
    // Create an instance of circuit
    let c = CircleDemo::<Bls12> {
        x: Fr::from_str("4"),
        y: Fr::from_str("3"),
        r: public_radius,
    };
    
    // Create a groth16 proof with our parameters.
    let proof = create_random_proof(c, &params, rng).unwrap();
        
    println!("Bob: Verifying...");

    assert!(verify_proof(
        &pvk,
        &proof,
        &[public_radius.unwrap()]
    ).unwrap());
}