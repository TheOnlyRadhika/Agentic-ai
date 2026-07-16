# Access Control

## Description
Access control ensures that only authorized users or contracts can execute privileged functions such as ownership transfers, upgrades, withdrawals, or administrative actions.

## Why it is dangerous
Missing or incorrect access control may allow any user to execute sensitive functions, resulting in theft of funds, ownership takeover, or permanent protocol damage.

## Common Attack Scenario
A publicly accessible administrative function allows an attacker to change the contract owner or withdraw protocol funds without authorization.

## Detection Hints
- Missing `onlyOwner` or role-based modifiers.
- Public administrative functions.
- Unrestricted ownership transfer.
- Privileged functions callable by arbitrary users.

## Mitigation
- Protect sensitive functions using `onlyOwner` or role-based access control.
- Apply the principle of least privilege.
- Regularly audit authorization logic.

## Severity
Critical

## References
- SWC-105: Unprotected Function
- OpenZeppelin AccessControl Documentation