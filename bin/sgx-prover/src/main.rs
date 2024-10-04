use automata_sgx_sdk::types::SgxStatus;

automata_sgx_sdk::enclave! {
    name: Prover,
    ecall: {
        fn run_prover() -> SgxStatus;
    }
}

fn main() {
    let result = Prover::new().run_prover().unwrap();
    assert!(result.is_success());
}
