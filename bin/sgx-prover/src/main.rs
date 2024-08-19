use automata_sgx_builder::types::SgxStatus;

automata_sgx_builder::enclave! {
    name: Prover,
    ecall: {
        fn run_prover() -> SgxStatus;
    }
}

fn main() {
    let result = Prover::new(true).unwrap().run_prover().unwrap();
    assert!(result.is_success());
}
