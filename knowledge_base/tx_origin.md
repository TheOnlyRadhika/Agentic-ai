# tx.origin Authentication

## Description
`tx.origin` returns the original externally owned account (EOA) that initiated the transaction.

## Why it is dangerous
Using `tx.origin` for authentication can allow phishing attacks where a malicious contract tricks a legitimate user into indirectly calling the victim contract.

## Common Attack Scenario
A victim signs a transaction to a malicious contract, which then calls the vulnerable contract. Since `tx.origin` remains the victim's address, authentication succeeds incorrectly.

## Detection Hints
- `tx.origin` used inside `require()`.
- Ownership checks based on `tx.origin`.

## Mitigation
- Always use `msg.sender` for authentication.
- Never rely on `tx.origin` for authorization logic.

## Severity
Medium

## References
- SWC-115: Authorization through tx.origin