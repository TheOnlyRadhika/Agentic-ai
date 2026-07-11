from dotenv import load_dotenv
import requests
import os
from collections import defaultdict

load_dotenv()

ETHERSCAN_KEY = os.getenv("ETHERSCAN_API_KEY")
if not ETHERSCAN_KEY:
    raise ValueError("ETHERSCAN_API_KEY not found. Check your .env file.")
BASE_URL = "https://api.etherscan.io/v2/api"



def get_contract_transactions(address: str,chainid: int = 1) -> dict:
    """
    Fetches last 500 transactions for a given contract address from Etherscan.
    
    Args:
        address (str): Ethereum contract address starting with 0x
        chainid (int): The chain ID for the network (default is 1 for Ethereum)
        
    Returns:
        dict with keys: transactions (list), total_fetched (int), error (str or None)
        
    Edge Cases:
        - Returns empty list if contract has no transactions
        - Returns error key if Etherscan rate limit hit
        - Returns error key if address is invalid
    """
    response = requests.get(BASE_URL, params={
            "chainid": chainid,
            "module": "account",
            "action": "txlist" ,  # what action fetches transaction list?
            "address": address ,    # what variable holds the address?
            "startblock":  0 , # from which block?
            "endblock":  99999999,   # to which block?
            "page":    1    , # which page?
            "offset":   500  ,  # how many transactions?
            "sort":    "desc"  ,   # newest first?
            "apikey":   ETHERSCAN_KEY    # which variable holds the key?

    })
    
    data = response.json()
    
    # if etherscan returns status "0" something went wrong
    if data["status"] != "1":
        return {   
            "success": False,
            "error_type": "etherscan_api",
            "message": data.get("message"),
            "details": data.get("result"),
            "raw_response": data
        }
    
    # return the good data
    return {
         "transactions" : data["result"],
            "total_fetched": len(data["result"]),
            "error" : None
    }


def get_contract_source(address: str, chainid: int = 1) -> dict:

    response = requests.get(BASE_URL, params={
        "chainid": chainid,
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": ETHERSCAN_KEY
    })
    data = response.json()
    if data["status"] != "1":
        return {
            "success": False,
            "message": data.get("message"),
            "details": data.get("result")
        }
    contract_data = data["result"][0]
    source_code = contract_data.get("SourceCode", "")
    if not source_code:
        return {
            "success": False,
            "verified": False,
            "message": "Contract source code is not verified on Etherscan."
        }
    return {
        "success": True,
        "verified": True,
        "contract_name": contract_data.get("ContractName"),
        "compiler_version": contract_data.get("CompilerVersion"),
        "source_code": source_code
    }



def compute_suspicious_patterns(transactions: list , address : str) -> dict:
    
    # group transactions by (caller, block_number)
    # filter for withdraw calls only
    grouped = defaultdict(list)
    
    for tx in transactions:
        if "withdraw" in tx.get("functionName", "").lower():
            key = ( tx["from"], tx["blockNumber"])
            grouped[key].append(tx)
    
    # find suspicious groups
    suspicious = {
        key: txs 
        for key, txs in grouped.items() 
        if len(txs) > 3
    }

    reentrancy_flags = []
    for key, txs in suspicious.items():
        attacker_address, block = key
        reentrancy_flags.append({
            "address": attacker_address,
            "block_number": block,
            "call_count": len(txs),
            "eth_drained": sum(int(tx["value"]) / 1e18 for tx in txs)
        })

    balance_drains = []
    for tx in transactions:
        value_eth = int(tx["value"])/1e18
        if value_eth > 10 and tx["from"].lower() == address.lower():
            # contract sent out more than 10 ETH in one transaction
            # this is suspicious
            balance_drains.append({
                "block_number": tx["blockNumber"],
                "eth_sent": round(value_eth, 4),
                "to": tx["to"],
                "tx_hash": tx["hash"]
            })
                
    first_time_sender_flags = []
    for tx in transactions:
        if int(tx.get("nonce", 1)) == 0:
            first_time_sender_flags.append({
                "address": tx["from"],
                "block_number": tx["blockNumber"],
                "tx_hash": tx["hash"]
            })
        
    return {
            "reentrancy_flags": reentrancy_flags,
            "balance_drains": balance_drains,
            "first_time_sender_flags": first_time_sender_flags,
            "total_suspicious_patterns": (
                len(reentrancy_flags)
                + len(balance_drains)
                + len(first_time_sender_flags)
            ),
            "transactions_scanned": len(transactions)
        }

def analyse_source_code(source_code: str) -> dict:
    """
    Analyzes the Solidity source code for potential vulnerabilities.
    
    Args:
        source_code (str): The Solidity source code of the contract.
    """
    findings = []
    if ".call(" in source_code or ".call{" in source_code:
        findings.append({
            "type": "external-call",
            "severity": "Medium",
            "description": "Low level call detected"
        })
    if "delegatecall" in source_code:
        findings.append({
            "type": "delegatecall",
            "severity": "high",
            "message": "delegatecall detected."
        })
    if "tx.origin" in source_code:
        findings.append({
            "type": "tx_origin",
            "severity": "medium",
            "message": "Authentication using tx.origin."
        })
    if "selfdestruct" in source_code:
        findings.append({
            "type": "selfdestruct",
            "severity": "high",
            "message": "Contract destruction capability detected."
        })
    if "assembly" in source_code:
        findings.append({
            "type": "assembly",
            "severity": "medium",
            "message": "Inline assembly detected."
        })
    return {
        "findings": findings,
        "total_findings": len(findings)
    }
            

TOOL_MAP = {
    "get_contract_transactions": lambda inp: get_contract_transactions(**inp),
    "compute_suspicious_patterns": lambda inp: compute_suspicious_patterns(**inp),
    "get_contract_source": lambda inp: get_contract_source(**inp),
    "analyse_source_code": lambda inp: analyse_source_code(inp["source_code"])
}


TOOL_DEFINITIONS = [
    {
        "name": "get_contract_transactions",
        "description": "Fetches the last 500 transactions from a specified Ethereum contract address on Etherscan. Call this first before any analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description":  "Ethereum contract address starting with 0x"
                },
                "chainid": {
                "type": "integer",
                "description": "Ethereum-compatible chain ID. Defaults to 1 for Ethereum Mainnet."
                }
            },
            "required": ["address"]
        }
    },
    {
        "name": "compute_suspicious_patterns",
        "description":  "Analyses a list of transactions to detect reentrancy attacks, large ETH drains, and new contract attackers. Call this after get_contract_transactions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description":  "Ethereum contract address being analysed"
                }
            },
            "required": ["address"]
        }
    },

    {
        "name": "get_contract_source",
        "description": "Fetches the verified Solidity source code of an Ethereum smart contract from Etherscan. Use this when source-code evidence would improve the security investigation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Ethereum contract address starting with 0x"
                },
                "chainid": {
                    "type": "integer",
                    "description": "Ethereum-compatible chain ID. Defaults to 1 for Ethereum Mainnet."
                }
            },
            "required": ["address"]
        }
    },
    {
        "name": "analyse_source_code",
        "description": "Performs static security analysis on the previously fetched Solidity source code of the contract.",
        "input_schema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Ethereum contract address being analysed."
                }
            },
            "required": ["address"]
        }
    }
]