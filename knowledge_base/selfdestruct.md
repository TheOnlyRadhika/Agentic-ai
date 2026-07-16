# Selfdestruct

## Description
`selfdestruct` permanently removes a contract from the blockchain and transfers any remaining Ether to a specified address.

## Why it is dangerous
If an attacker gains permission to invoke `selfdestruct`, they can permanently disable the contract and potentially redirect remaining funds.

## Common Attack Scenario
A compromised owner account calls `selfdestruct`, permanently disabling protocol functionality.

## Detection Hints
- Presence of the `selfdestruct` keyword.
- Lack of access control around destruction logic.

## Mitigation
- Avoid using `selfdestruct` unless absolutely necessary.
- Restrict its execution to authorized administrators.

## Severity
High

## References
- SWC-106: Unprotected SELFDESTRUCT