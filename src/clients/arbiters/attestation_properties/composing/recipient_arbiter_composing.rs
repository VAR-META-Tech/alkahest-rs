use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol! {
    contract RecipientArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            address recipient;
        }
    }
}

crate::impl_encode_and_decode!(
    RecipientArbiterComposing,
    encode_recipient_arbiter_composing_demand,
    decode_recipient_arbiter_composing_demand
);

crate::impl_arbiter_api!(
    RecipientArbiterComposingApi,
    RecipientArbiterComposing::DemandData,
    encode_recipient_arbiter_composing_demand,
    decode_recipient_arbiter_composing_demand
);
