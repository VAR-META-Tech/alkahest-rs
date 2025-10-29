use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    AllArbiter,
    "src/contracts/arbiters/AllArbiter.json"
);

use AllArbiter::DemandData;

impl From<DemandData> for alloy::primitives::Bytes {
    fn from(demand: DemandData) -> Self {
        use alloy::sol_types::SolValue as _;
        demand.abi_encode().into()
    }
}

impl TryFrom<&alloy::primitives::Bytes> for DemandData {
    type Error = eyre::Error;

    fn try_from(data: &alloy::primitives::Bytes) -> Result<Self, Self::Error> {
        use alloy::sol_types::SolValue as _;
        Ok(Self::abi_decode(data)?)
    }
}

impl TryFrom<alloy::primitives::Bytes> for DemandData {
    type Error = eyre::Error;

    fn try_from(data: alloy::primitives::Bytes) -> Result<Self, Self::Error> {
        use alloy::sol_types::SolValue as _;
        Ok(Self::abi_decode(&data)?)
    }
}

crate::impl_encode_and_decode!(
    AllArbiter,
    encode_all_arbiter_demand,
    decode_all_arbiter_demand
);

// API implementation
crate::impl_arbiter_api!(
    AllArbiterApi,
    AllArbiter::DemandData,
    encode_all_arbiter_demand,
    decode_all_arbiter_demand,
    all_arbiter
);
