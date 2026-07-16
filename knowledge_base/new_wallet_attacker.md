# First-Time Sender Activity

## Description
Transactions originating from newly created wallets are not inherently malicious. However, attackers often use fresh addresses to avoid detection, reputation tracking, and blacklist mechanisms.

## Why it is dangerous
New wallets frequently appear during exploit attempts because attackers prefer disposable addresses with no transaction history.

## Common Attack Scenario
An attacker creates a new wallet immediately before interacting with a vulnerable smart contract, performs the exploit, transfers stolen funds through several intermediate wallets, and abandons the original address.

## Detection Hints
- Sender nonce equals zero.
- No prior transaction history.
- First interaction is with a high-value smart contract.

## Mitigation
- Combine this indicator with other suspicious behaviors.
- Monitor new addresses performing unusually large or privileged actions.
- Do not rely on this signal alone for risk assessment.

## Severity
Low

## References
- Chainalysis Investigation Reports
- Ethereum Security Best Practices