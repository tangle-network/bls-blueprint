fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/main.rs");
    blueprint_metadata::generate_json();

    let contract_dirs: Vec<&str> = vec!["./contracts"];
    blueprint_build_utils::soldeer_update();
    blueprint_build_utils::build_contracts(contract_dirs);
}
