import anthropic
#import os
#from groq import Groq
import json
from tools import TOOL_MAP , TOOL_DEFINITIONS

SYSTEM_PROMPT = """
You are an expert DeFi security analyst agent.

You analyse Ethereum smart contracts for signs of exploitation.

YOUR PROCESS — follow this exact order every time:
1. Call get_contract_transactions with the contract address
2. Call compute_suspicious_patterns with the transactions and address
3. Reason about the patterns you find
4. Produce a final security report

YOUR REPORT must include:
- Risk score: 1 to 10 (10 = definitely exploited)
- Attack type: reentrancy / balance drain / new contract attacker / none
- Evidence: specific block numbers and addresses that triggered flags
- Plain English explanation: what happened and why it's suspicious

RULES:
- Never skip step 1 or step 2
- Never guess — only use data from your tools
- Think step by step before writing your report
- If no suspicious patterns found, say so clearly with risk score 1-2
"""

def run_agent(address: str) -> dict:

    client = anthropic.Anthropic()
    #client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    messages = [{
        "role" : "user",
        "content" : f"Analyse this smart contract for security exploits : {address}"

    }]
    print(f" \n Agent starting analysis on : {address}\n")

    step = 0
    MAX_STEPS = 10
    while step < MAX_STEPS:
        step += 1
        print(f"── Step {step} ──────────────")
            
        response = client.messages.create(
            model="claude-sonnet-4-6",
            #model="llama-3.3-70b-versatile",
            max_tokens=1000,
            temperature=0,
            system=SYSTEM_PROMPT,
            tools=TOOL_DEFINITIONS,
            messages=messages
        )
            
        print(f"stop_reason: {response.stop_reason}")

        if response.stop_reason == "end_turn":
            final_report = ""
            for block in response.content:
                if hasattr(block, "text"):
                    final_report += block.text
            print("\n✓ Analysis complete.\n")
            return {"status": "success", "report": final_report}


        if response.stop_reason == "tool_use":
            # add model response to history
            messages.append({"role": "assistant", "content": response.content})
                    
            # find and run each tool the model requested
            results = []
            for block in response.content:
                if block.type == "tool_use":
                    print(f"  → calling: {block.name}")
                    print(f"  → inputs:  {block.input}")
                            
                    # run the real function using TOOL_MAP
                    tool_fn = TOOL_MAP[block.name]
                    result = tool_fn(block.input)
                            
                    print(f"  → result:  {result}\n")
                            
                    results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result)
                    })
                    
                    # feed results back to model
            messages.append({"role": "user", "content": results})
    return {"status": "error", "report": "Agent hit maximum steps. Analysis incomplete."}