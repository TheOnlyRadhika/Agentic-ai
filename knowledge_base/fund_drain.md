# Large Fund Drain

## Description
A large fund drain occurs when a smart contract transfers a significant amount of Ether or tokens in a single transaction or over a short period. While legitimate treasury operations exist, unusually large transfers may indicate exploitation or unauthorized fund movement.

## Why it is dangerous
Unexpected large outflows can signal that an attacker has successfully exploited a vulnerability such as reentrancy, compromised access control, or flash loan manipulation.

## Common Attack Scenario
After exploiting a vulnerability, an attacker rapidly transfers a large amount of assets from the contract to their own wallet before the protocol can respond.

## Detection Hints
- Large outgoing Ether transfers.
- Multiple high-value withdrawals in a short period.
- Sudden reduction in contract balance.
- Transfers to previously unseen addresses.

## Mitigation
- Implement withdrawal limits where appropriate.
- Monitor treasury transactions.
- Protect privileged functions with strong access control.
- Deploy on-chain monitoring and alerting systems.

## Severity
High

## References
- SWC Registry
- ConsenSys Smart Contract Best Practices