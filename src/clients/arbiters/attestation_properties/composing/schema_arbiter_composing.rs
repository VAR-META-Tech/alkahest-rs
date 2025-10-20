use alloy::sol;

sol! {
    contract SchemaArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            bytes32 schema;
        }
    }
}

crate::impl_encode_and_decode!(
    SchemaArbiterComposing,
    encode_schema_arbiter_composing_demand,
    decode_schema_arbiter_composing_demand
);