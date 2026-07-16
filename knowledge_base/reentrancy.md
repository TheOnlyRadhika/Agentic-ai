# Reentrancy

## Description
Reentrancy occurs when a contract transfers Ether or control to another contract before updating its internal state.

## Why it is dangerous
An attacker can repeatedly re-enter the vulnerable function and withdraw funds multiple times before the contract updates its balance.

## Common Attack Scenario
The DAO attack exploited a reentrancy vulnerability to drain millions of Ether from the protocol.

## Detection Hints
- Use of `.call()` or `.call{value: ...}`.
- External calls before state updates.
- Missing reentrancy protection.

## Mitigation
- Follow the Checks-Effects-Interactions pattern.
- Update state before making external calls.
- Use `ReentrancyGuard` where appropriate.

## Severity
High

## References
- SWC-107: Reentrancy