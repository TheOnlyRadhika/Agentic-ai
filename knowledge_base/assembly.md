# Inline Assembly

## Description
Inline assembly allows developers to write low-level Ethereum Virtual Machine (EVM) instructions directly inside Solidity.

## Why it is dangerous
Assembly bypasses many of Solidity's built-in safety checks, making the code more difficult to audit and increasing the risk of subtle bugs.

## Common Attack Scenario
Incorrect memory or storage manipulation inside assembly blocks can introduce vulnerabilities that are difficult to detect through standard code review.

## Detection Hints
- Presence of `assembly { ... }` blocks.
- Manual storage or memory manipulation.

## Mitigation
- Use Solidity whenever possible.
- Keep assembly blocks minimal and well documented.
- Thoroughly audit assembly code.



## Severity
Medium

## References
- Solidity Inline Assembly Documentation