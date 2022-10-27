use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Empty, Addr};
use cw2::set_contract_version;
pub use cw721_archid::{ContractError, InstantiateMsg, MintMsg, MinterResponse, QueryMsg};
use cw721_updatable::{Expiration, ContractInfoResponse};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema, Debug)]
pub struct Subdomain {
    name: Option<String>,
    resolver: Option<Addr>,
    minted: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema, Debug)]
pub struct Account {
  username: Option<String>,
  profile: Option<String>,
  account_type: Option<String>,
  verfication_hash: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema, Debug)]
pub struct Website {
  url: Option<String>,
  domain: Option<String>,
  verfication_hash: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema, Debug)]
pub struct Metadata {
  pub name: Option<String>,         // e.g. for interoperability with external marketplaces
  pub description: Option<String>,  // e.g. ibid.
  pub image: Option<String>,        // e.g. ibid.
  pub expiry: Option<Expiration>,
  pub domain: Option<String>,
  pub subdomains: Option<Vec<Subdomain>>,
  pub accounts: Option<Vec<Account>>,
  pub websites: Option<Vec<Website>>,
}

pub type Extension = Option<Metadata>;

pub type Cw721MetadataContract<'a> = cw721_archid::Cw721Contract<'a, Extension, Empty, Empty, Empty>;

pub type ExecuteMsg = cw721_archid::ExecuteMsg<Extension, Empty>;
pub type UpdateMetadataMsg = cw721_archid::msg::UpdateMetadataMsg<Extension>;

const CONTRACT_NAME: &str = "crates.io:archid-token";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod entry {
    use super::*;

    #[cfg(not(feature = "library"))]
    use cosmwasm_std::entry_point;
    use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};

    #[cfg_attr(not(feature = "library"), entry_point)]
    pub fn instantiate(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> StdResult<Response> {
        set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

        let info = ContractInfoResponse {
            name: msg.name,
            symbol: msg.symbol,
        };
        Cw721MetadataContract::default()
            .contract_info
            .save(deps.storage, &info)?;
        let minter = deps.api.addr_validate(&msg.minter)?;
        Cw721MetadataContract::default()
            .minter
            .save(deps.storage, &minter)?;
        Ok(Response::default())
    }

    #[cfg_attr(not(feature = "library"), entry_point)]
    pub fn execute(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        msg: ExecuteMsg,
    ) -> Result<Response, ContractError> {
        Cw721MetadataContract::default().execute(deps, env, info, msg)
    }

    #[cfg_attr(not(feature = "library"), entry_point)]
    pub fn query(deps: Deps, env: Env, msg: QueryMsg<Empty>) -> StdResult<Binary> {
        Cw721MetadataContract::default().query(deps, env, msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cw721_updatable::{Cw721Query, NftInfoResponse};

    const CREATOR: &str = "creator";

    #[test]
    fn use_metadata_extension() {
        let mut deps = mock_dependencies();
        let contract = Cw721MetadataContract::default();

        let info = mock_info(CREATOR, &[]);
        let init_msg = InstantiateMsg {
            name: "archid token".to_string(),
            symbol: "AID".to_string(),
            minter: CREATOR.to_string(),
        };
        contract
            .instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg)
            .unwrap();

        let resolver_addr = Addr::unchecked("archway1yvnw8xj5elngcq95e2n2p8f80zl7shfwyxk88858pl6cgzveeqtqy7xtf7".to_string()); 

        let subdomain1 = Subdomain {
            name: Some("game".to_string()),
            resolver: Some(resolver_addr.clone()),
            minted: Some(false),
        };
        let subdomain2 = Subdomain {
            name: Some("dapp".to_string()),
            resolver: Some(resolver_addr.clone()),
            minted: Some(false),
        };
        let subdomain3 = Subdomain {
            name: Some("market".to_string()),
            resolver: Some(resolver_addr.clone()),
            minted: Some(false),
        };

        let subdomains = vec![
            subdomain1, 
            subdomain2, 
            subdomain3
        ];

        let accounts = vec![
            Account {
                username: Some("drew@chainofinsight.com".to_string()),
                profile: None,
                account_type: Some("email".to_string()),
                verfication_hash: None, // XXX: Only "self attestations" for now
            },
            Account {
                username: Some("@chainofinsight".to_string()),
                profile: Some("twitter.com/chainofinsight".to_string()),
                account_type: Some("twitter".to_string()),
                verfication_hash: None,
            }
        ];
    
        let websites = vec![
            Website {
                url: Some("drewstaylor.com".to_string()),
                domain: Some("drewstaylor.arch".to_string()),
                verfication_hash: None,
            },
            Website {
                url: Some("game.drewstaylor.com".to_string()),
                domain: Some("game.drewstaylor.arch".to_string()),
                verfication_hash: None,
            },
            Website {
                url: Some("dapp.drewstaylor.com".to_string()),
                domain: Some("dapp.drewstaylor.arch".to_string()),
                verfication_hash: None,
            },
            Website {
                url: Some("market.drewstaylor.com".to_string()),
                domain: Some("market.drewstaylor.arch".to_string()),
                verfication_hash: None,
            }
        ];
    
        let metadata_extension = Some(Metadata {
            name: Some("drewstaylor.arch".into()),
            description: Some("default token description".into()),
            image: Some("ipfs://QmZdPdZzZum2jQ7jg1ekfeE3LSz1avAaa42G6mfimw9TEn".into()),
            domain: Some("drewstaylor.arch".into()),
            expiry: Some(Expiration::AtHeight(1234567)),
            subdomains: Some(subdomains),
            accounts: Some(accounts),
            websites: Some(websites),
        });

        let token_id = "drewstaylor.arch";
        let mint_msg = MintMsg {
            token_id: token_id.to_string(),
            owner: CREATOR.to_string(),
            token_uri: None,
            extension: metadata_extension,
        };
        let exec_msg = ExecuteMsg::Mint(mint_msg.clone());
        contract
            .execute(deps.as_mut(), mock_env(), info, exec_msg)
            .unwrap();

        let res = contract.nft_info(deps.as_ref(), token_id.into()).unwrap();

        assert_eq!(res.token_uri, mint_msg.token_uri);
        assert_eq!(res.extension, mint_msg.extension);
    }

    #[test]
    fn updating_metadata() {
        let mut deps = mock_dependencies();
        let contract = Cw721MetadataContract::default();

        let info = mock_info(CREATOR, &[]);
        let init_msg = InstantiateMsg {
            name: "archid token".to_string(),
            symbol: "AID".to_string(),
            minter: CREATOR.to_string(),
        };
        contract
            .instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg)
            .unwrap();

        let token_id1 = "updatable".to_string();
        let token_id2 = "won't be updated".to_string();

        let metadata_extension = Some(Metadata {
            name: Some("original.arch".into()),
            description: Some("default token description".into()),
            image: Some("ipfs://QmZdPdZzZum2jQ7jg1ekfeE3LSz1avAaa42G6mfimw9TEn".into()),
            domain: Some("original.arch".into()),
            expiry: Some(Expiration::AtHeight(1234567)),
            subdomains: None,
            accounts: None,
            websites: None,
        });

        let modified_metadata_extension = Some(Metadata {
            name: Some("modified.arch".into()),
            description: Some("default token description".into()),
            image: Some("ipfs://QmZdPdZzZum2jQ7jg1ekfeE3LSz1avAaa42G6mfimw9TEn".into()),
            domain: Some("modified.arch".into()),
            expiry: Some(Expiration::AtHeight(1234567)),
            subdomains: None,
            accounts: None,
            websites: None,
        });

        let mint_msg = ExecuteMsg::Mint(MintMsg {
            token_id: token_id1.clone(),
            owner: CREATOR.to_string(),
            token_uri: None,
            extension: metadata_extension.clone(),
        });

        let mint_msg2 = ExecuteMsg::Mint(MintMsg {
            token_id: token_id2.clone(),
            owner: "innocent hodlr".to_string(),
            token_uri: None,
            extension: metadata_extension.clone(),
        });

        let err_metadata_extension = Some(Metadata {
            name: Some("evil doer".into()),
            description: Some("has rugged your token".into()),
            image: Some("rugged".into()),
            domain: None,
            expiry: None,
            subdomains: None,
            accounts: None,
            websites: None,
        });

        let update_msg = ExecuteMsg::UpdateMetadata(UpdateMetadataMsg {
            token_id: token_id1.clone(),
            extension: modified_metadata_extension.clone(),
        });

        let err_update_msg = ExecuteMsg::UpdateMetadata(UpdateMetadataMsg {
            token_id: token_id1.clone(),
            extension: err_metadata_extension.clone(),
        });

        let err_update_msg2 = ExecuteMsg::UpdateMetadata(UpdateMetadataMsg {
            token_id: token_id2.clone(),
            extension: err_metadata_extension.clone(),
        });

        // Mint
        let admin = mock_info(CREATOR, &[]);
        let _mint1 = contract
            .execute(deps.as_mut(), mock_env(), admin.clone(), mint_msg)
            .unwrap();

        let _mint2 = contract
            .execute(deps.as_mut(), mock_env(), admin.clone(), mint_msg2)
            .unwrap();

        // Original NFT infos are correct
        let info1 = contract.nft_info(deps.as_ref(), token_id1.clone()).unwrap();
        assert_eq!(
            info1,
            NftInfoResponse {
                token_uri: None,
                extension: metadata_extension.clone(),
            }
        );

        let info2 = contract.nft_info(deps.as_ref(), token_id2.clone()).unwrap();
        assert_eq!(
            info2,
            NftInfoResponse {
                token_uri: None,
                extension: metadata_extension.clone(),
            }
        );

        // Random cannot update NFT
        let random = mock_info("random", &[]);
        
        let err = contract
            .execute(deps.as_mut(), mock_env(), random, err_update_msg)
            .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        // Admin can't rug owners
        let err2 = contract
            .execute(deps.as_mut(), mock_env(), admin.clone(), err_update_msg2)
            .unwrap_err();
        assert_eq!(err2, ContractError::Unauthorized {});

        // Only allowed minters can update NFT
        let _update = contract
            .execute(deps.as_mut(), mock_env(), admin.clone(), update_msg)
            .unwrap();

        let update_info = contract.nft_info(deps.as_ref(), token_id1.clone()).unwrap();

        // Modified NFT info is correct
        assert_eq!(
            update_info,
            NftInfoResponse {
                token_uri: None,
                extension: modified_metadata_extension,
            }
        );
    }

    #[test]
    fn burning_admin_only() {
        let mut deps = mock_dependencies();
        let contract = Cw721MetadataContract::default();

        let info = mock_info(CREATOR, &[]);
        let init_msg = InstantiateMsg {
            name: "archid token".to_string(),
            symbol: "AID".to_string(),
            minter: CREATOR.to_string(),
        };
        contract
            .instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg)
            .unwrap();

        let token_id = "petrify".to_string();
        let token_uri = "https://www.merriam-webster.com/dictionary/petrify".to_string();

        let mint_msg = ExecuteMsg::Mint(MintMsg {
            token_id: token_id.clone(),
            owner: "someone".to_string(),
            token_uri: Some(token_uri),
            extension: None,
        });

        let burn_msg = ExecuteMsg::BurnAdminOnly { token_id };

        // Mint NFT
        let admin = mock_info(CREATOR, &[]);
        let _ = contract
            .execute(deps.as_mut(), mock_env(), admin.clone(), mint_msg)
            .unwrap();

        // Owner not allowed to burn as admin
        let owner = mock_info("someone", &[]);
        let err = contract
            .execute(deps.as_mut(), mock_env(), owner, burn_msg.clone())
            .unwrap_err();

        assert_eq!(err, ContractError::Unauthorized {});

        // Admin can burn tokens owned by anyone
        let _ = contract
            .execute(deps.as_mut(), mock_env(), admin, burn_msg)
            .unwrap();

        // Ensure num tokens decreases
        let count = contract.num_tokens(deps.as_ref()).unwrap();
        assert_eq!(0, count.count);

        // Requesting NFT metadata returns error
        let _ = contract
            .nft_info(deps.as_ref(), "petrify".to_string())
            .unwrap_err();

        // Listing token_ids should now be empty
        let tokens = contract.all_tokens(deps.as_ref(), None, None).unwrap();
        assert!(tokens.tokens.is_empty());
    }
}
