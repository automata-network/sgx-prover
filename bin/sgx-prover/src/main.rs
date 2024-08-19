use automata_sgx_builder::types::SgxStatus;

// automata_sgx_builder::enclave! {
//     name: ScrollStatelessBlockVerifier,
//     ecall: {
//         fn run_server() -> SgxStatus;
//     }
// }

automata_sgx_builder::enclave! {
    name: Prover,
    ecall: {
        fn run_prover() -> SgxStatus;
    }
}

// automata_sgx_builder::enclave! {
//     name: DcapTest,
//     ecall: {
//         fn run_dcap_test() -> SgxStatus;
//     }
// }

// automata_sgx_builder::enclave! {
//     name: TlsServer,
//     ecall: {
//         fn run_server() -> SgxStatus;
//     }
// }

fn main() {
    // let verifier = ScrollStatelessBlockVerifier::new(true).unwrap();
    // let result = verifier.run_server().unwrap();
    // assert!(result.is_success());

    let result = Prover::new(true).unwrap().run_prover().unwrap();
    // let result = TlsServer::new(true).unwrap().run_server().unwrap();

    // println!("hello");
    // let result = DcapTest::new(true).unwrap().run_dcap_test().unwrap();
    assert!(result.is_success());
}
