use bls_blueprint_lib::{keygen, sign};
use blueprint_sdk::build;
use blueprint_sdk::tangle::blueprint;
use std::path::Path;
use std::process;

fn main() {
    let contract_dirs: Vec<&str> = vec!["contracts"];
    build::soldeer_install();
    build::soldeer_update();
    build::build_contracts(contract_dirs);

    println!("cargo::rerun-if-changed=../src");

    let blueprint = blueprint! {
        name: "bls-blueprint",
        master_manager_revision: "Latest",
        manager: { Evm = "BlsBlueprint" },
        jobs: [keygen, sign]
    };

    match blueprint {
        Ok(blueprint) => {
            // TODO: Should be a helper function probably
            let json = blueprint_sdk::tangle::metadata::macros::ext::serde_json::to_string_pretty(
                &blueprint,
            )
            .unwrap();
            std::fs::write(
                Path::new(env!("CARGO_WORKSPACE_DIR")).join("blueprint.json"),
                json.as_bytes(),
            )
            .unwrap();
        }
        Err(e) => {
            println!("cargo::error={e:?}");
            process::exit(1);
        }
    }
}
