# Delegatecall

## Description
`delegatecall` executes code from another contract while preserving the storage, balance, and execution context of the calling contract.

## Why it is dangerous
Improper use of `delegatecall` can allow external code to modify the caller's storage, including critical variables such as ownership, balances, or permissions.

## Common Attack Scenario
Many upgradeable proxy contracts rely on `delegatecall`. If the implementation contract is malicious or insufficiently protected, an attacker may gain control over the proxy contract.

## Detection Hints
- Presence of the `delegatecall` keyword.
- Delegatecall to arbitrary or user-controlled addresses.
- Missing access control around delegatecall.

## Mitigation
- Restrict delegatecall to trusted implementation contracts.
- Protect delegatecall with access control such as `onlyOwner`.
- Carefully audit upgrade mechanisms.

## Severity
High


## References
- SWC-112: Delegatecall to Untrusted Callee
- Solidity Documentation