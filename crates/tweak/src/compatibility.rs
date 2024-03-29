//! Compatibility check of tweaking an on-chain contract with a local cloned project.
//! The local project usually should be created by `forge clone` command.
//! Users may modify the source code of the cloned project, but the storage layout should remain the same as the original contract.

use std::collections::BTreeMap;

use foundry_compilers::artifacts::StorageLayout;

use crate::metadata::ClonedProject;

/// Check the tweak compatibility of the project with the given root.
/// The project is compatible if:
/// - the project's storage layout is the same as the original contract.
/// If the project is not compatible, an error is returned.
pub fn check_storage_compatibility(cloned_project: &ClonedProject) -> eyre::Result<()> {
    // to check the storage layout compatibility, we need to download the original contract's code from etherscan and compile.
    let original_layout = cloned_project.metadata.storage_layout.to_owned();
    let current_layout = cloned_project
        .main_artifact()?
        .storage_layout
        .to_owned()
        .expect("storage layout is missing");
    check_storage_layout_compatibility(&original_layout, &current_layout)
}

/// Check that the current storage layout is compatible with the original storage layout.
/// Each state variable in the original storage layout should have the same slot in the current storage layout.
pub fn check_storage_layout_compatibility(
    original: &StorageLayout,
    current: &StorageLayout,
) -> eyre::Result<()> {
    // check storage types
    for (type_name, original_type) in original.types.iter() {
        let current_type = current.types.get(type_name);
        if current_type.is_none() {
            return Err(eyre::eyre!(
                "the storage type {} is missing in the current contract",
                type_name
            ));
        }
        let current_type = current_type.unwrap();
        if original_type != current_type {
            return Err(eyre::eyre!(
                "the storage type {} has different layout in the current contract",
                type_name
            ));
        }
    }

    // check storage variables
    let current_storage_var_map = BTreeMap::from_iter(
        current.storage.iter().map(|v| (format!("{}:{}", v.contract, v.label), v)),
    );
    for original_var in original.storage.iter() {
        let current_var = current_storage_var_map
            .get(&format!("{}:{}", original_var.contract, original_var.label));
        if current_var.is_none() {
            return Err(eyre::eyre!(
                "the storage variable {} is missing in the current contract",
                original_var.label
            ));
        }
        let current_var = current_var.unwrap();
        // offset, slot, type should be the same
        if original_var.offset != current_var.offset
            || original_var.slot != current_var.slot
            || original_var.storage_type != current_var.storage_type
        {
            return Err(eyre::eyre!(
                "the storage variable {} has different layout in the current contract",
                original_var.label
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use foundry_compilers::artifacts::StorageLayout;

    fn load_json_layout(json_str: &str) -> StorageLayout {
        serde_json::from_str(json_str).unwrap()
    }

    #[test]
    pub fn test_same_storage_layout() {
        let storage = load_json_layout(
            r#"{
                "storage": [
                  {
                    "astId": 3,
                    "contract": "contract.sol:C",
                    "label": "data",
                    "offset": 0,
                    "slot": "0",
                    "type": "t_uint256"
                  },
                  {
                    "astId": 5,
                    "contract": "contract.sol:C",
                    "label": "owner",
                    "offset": 0,
                    "slot": "1",
                    "type": "t_address"
                  }
                ],
                "types": {
                  "t_address": {
                    "encoding": "inplace",
                    "label": "address",
                    "numberOfBytes": "20"
                  },
                  "t_uint256": {
                    "encoding": "inplace",
                    "label": "uint256",
                    "numberOfBytes": "32"
                  }
                }
            }"#,
        );

        assert!(super::check_storage_layout_compatibility(&storage, &storage).is_ok());
    }

    #[test]
    pub fn test_storage_layout_shift() {
        let original = load_json_layout(
            r#"{
            "storage": [
              {
                "astId": 3,
                "contract": "contract.sol:C",
                "label": "data",
                "offset": 0,
                "slot": "0",
                "type": "t_uint256"
              }
            ],
            "types": {
              "t_uint256": {
                "encoding": "inplace",
                "label": "uint256",
                "numberOfBytes": "32"
              }
            }
        }"#,
        );
        let current = load_json_layout(
            r#"{
            "storage": [
              {
                "astId": 3,
                "contract": "contract.sol:C",
                "label": "data",
                "offset": 0,
                "slot": "1",
                "type": "t_uint256"
              }
            ],
            "types": {
              "t_uint256": {
                "encoding": "inplace",
                "label": "uint256",
                "numberOfBytes": "32"
              }
            }
        }"#,
        );
        assert!(super::check_storage_layout_compatibility(&original, &current).is_err());
    }

    #[test]
    pub fn test_storage_layout_different_type() {
        let original = load_json_layout(
            r#"{
        "storage": [
          {
            "astId": 3,
            "contract": "contract.sol:C",
            "label": "data",
            "offset": 0,
            "slot": "0",
            "type": "t_uint256"
          }
        ],
        "types": {
          "t_uint256": {
            "encoding": "inplace",
            "label": "uint256",
            "numberOfBytes": "32"
          }
        }
    }"#,
        );
        let current = load_json_layout(
            r#"{
        "storage": [
          {
            "astId": 3,
            "contract": "contract.sol:C",
            "label": "data",
            "offset": 0,
            "slot": "1",
            "type": "t_address"
          }
        ],
        "types": {
          "t_address": {
            "encoding": "inplace",
            "label": "address",
            "numberOfBytes": "20"
          }
        }
    }"#,
        );
        assert!(super::check_storage_layout_compatibility(&original, &current).is_err());
    }

    #[test]
    pub fn test_storage_layout_additional() {
        let original = load_json_layout(
            r#"{
        "storage": [
          {
            "astId": 3,
            "contract": "contract.sol:C",
            "label": "data",
            "offset": 0,
            "slot": "0",
            "type": "t_uint256"
          }
        ],
        "types": {
          "t_uint256": {
            "encoding": "inplace",
            "label": "uint256",
            "numberOfBytes": "32"
          }
        }
    }"#,
        );
        let current = load_json_layout(
            r#"{
              "storage": [
                {
                  "astId": 3,
                  "contract": "contract.sol:C",
                  "label": "data",
                  "offset": 0,
                  "slot": "0",
                  "type": "t_uint256"
                },
                {
                  "astId": 5,
                  "contract": "contract.sol:C",
                  "label": "owner",
                  "offset": 0,
                  "slot": "1",
                  "type": "t_address"
                }
              ],
              "types": {
                "t_address": {
                  "encoding": "inplace",
                  "label": "address",
                  "numberOfBytes": "20"
                },
                "t_uint256": {
                  "encoding": "inplace",
                  "label": "uint256",
                  "numberOfBytes": "32"
                }
              }
            }"#,
        );
        assert!(super::check_storage_layout_compatibility(&original, &current).is_ok());
    }
}
