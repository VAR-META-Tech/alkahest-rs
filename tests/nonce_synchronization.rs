#[cfg(test)]
mod tests {
    use alkahest_rs::{
        DefaultAlkahestClient,
        extensions::{HasAttestation, HasErc20, HasStringObligation},
        fixtures::MockERC20Permit,
        types::{ApprovalPurpose, ArbiterData, Erc20Data},
        utils::TestContext,
    };
    use alloy::{
        primitives::{Bytes, U256, bytes},
        providers::Provider,
    };
    use std::{
        thread::sleep,
        time::{SystemTime, UNIX_EPOCH},
    };

    use alkahest_rs::utils::setup_test_environment;

    #[tokio::test]
    async fn test_nonce_synchronization_across_modules() -> eyre::Result<()> {
        let test = setup_test_environment().await?;

        let mock_erc20_a = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20_a
            .transfer(test.alice.address(), U256::from(500))
            .send()
            .await?
            .get_receipt()
            .await?;

        // This test reproduces the "nonce too low" error by calling functions
        // across different submodules that should share the same wallet provider

        let initial_nonce = test
            .alice_client
            .wallet_provider
            .get_transaction_count(test.alice.address())
            .await?;

        println!("Initial nonce: {}", initial_nonce);

        // First call - ERC20 module
        let mock_erc20 = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20
            .transfer(test.alice.address(), 200u64.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        let price = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: U256::from(100),
        };

        // Create custom arbiter data
        let arbiter = test.addresses.erc20_addresses.clone().payment_obligation;
        let demand = Bytes::from(b"custom demand data");
        let item = ArbiterData { arbiter, demand };

        // approve tokens for escrow
        test.alice_client
            .erc20()
            .approve(&price, ApprovalPurpose::Escrow)
            .await?;
        // Call ERC20 module

        let receipt = test
            .alice_client
            .erc20()
            .buy_with_erc20(&price, &item, 0)
            .await?;

        let nonce_after_erc20 = test
            .alice_client
            .wallet_provider
            .get_transaction_count(test.alice.address())
            .await?;

        println!("Nonce after ERC20 call: {}", nonce_after_erc20);

        // Call StringObligation module (different module)
        let string_receipt = test
            .alice_client
            .string_obligation()
            .do_obligation("test obligation".to_string(), None)
            .await?;

        let nonce_after_string = test
            .alice_client
            .wallet_provider
            .get_transaction_count(test.alice.address())
            .await?;

        println!("Nonce after StringObligation call: {}", nonce_after_string);

        sleep(std::time::Duration::from_secs(1));

        // Call ERC20 module again (should work without nonce conflicts)
        let price2 = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 50u64.try_into()?,
        };

        println!("About to make second ERC20 call...");

        // Let's check the nonce right before the call
        let pre_call_nonce = test
            .alice_client
            .wallet_provider
            .get_transaction_count(test.alice.address())
            .await?;
        println!("Nonce right before second ERC20 call: {}", pre_call_nonce);

        // Try adding a small delay to ensure nonce state is synchronized
        sleep(std::time::Duration::from_millis(100));
        test.alice_client
            .erc20()
            .approve(&price, ApprovalPurpose::Escrow)
            .await?;

        println!("Approved tokens for second ERC20 call.");

        let erc20_receipt2 = test
            .alice_client
            .erc20()
            .buy_with_erc20(&price2, &item, 0)
            .await?;

        let final_nonce = test
            .alice_client
            .wallet_provider
            .get_transaction_count(test.alice.address())
            .await?;

        println!("Final nonce: {}", final_nonce);

        // Verify that all transactions were successful
        assert!(string_receipt.status());
        assert!(erc20_receipt2.status());

        // Verify nonces increased correctly
        assert!(final_nonce > initial_nonce);
        println!("✅ Nonce synchronization test passed");

        Ok(())
    }
}
