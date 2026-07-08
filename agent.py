import os
import json
from unittest import result
from groq import Groq
from tools import TOOL_MAP, TOOL_DEFINITIONS
from dotenv import load_dotenv

load_dotenv()

# Convert Anthropic tool format to OpenAI/Groq format
def convert_tools_for_groq(tool_definitions):
    groq_tools = []
    for tool in tool_definitions:
        groq_tools.append({
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["input_schema"]
            }
        })
    return groq_tools

GROQ_TOOLS = convert_tools_for_groq(TOOL_DEFINITIONS)

SYSTEM_PROMPT = """
        You are an autonomous Ethereum Smart Contract Security Analyst.

        Your primary objective is to determine whether a smart contract shows evidence of vulnerabilities, exploitation, or suspicious behaviour.

        You are an investigator, not a report generator.

        -------------------------
        INVESTIGATION STRATEGY
        -------------------------

        Before taking any action:

        1. Identify what information is currently available.
        2. Determine what information is missing.
        3. Choose the investigative tool that best reduces this uncertainty.
        4. After every tool result, reassess whether additional investigation is required.
        5. Continue gathering evidence until you are confident that a conclusion can be supported.

        Never perform unnecessary tool calls.

        -------------------------
        REASONING PRINCIPLES
        -------------------------

        Base every conclusion on evidence returned by tools.

        Never fabricate blockchain data.

        Never assume that the absence of evidence proves that the contract is safe.

        If evidence is insufficient, clearly explain what information is missing.

        If multiple independent pieces of evidence point toward the same attack pattern, increase confidence in your conclusion.

        -------------------------
        REPORT FORMAT
        -------------------------

        Produce a structured report containing:

        1. Executive Summary

        2. Risk Score (1-10)

        3. Confidence Score (0-100%)

        4. Security Findings

        5. Evidence Collected
        - Block Numbers
        - Addresses
        - Transactions

        6. Reasoning
        Explain how the collected evidence supports each finding.

        7. Investigation Limitations

        8. Recommended Next Steps

        Your goal is not to call every available tool.

        Your goal is to gather enough evidence to make the best possible security assessment.
    """


def run_agent(address: str) -> dict:

    client = Groq(api_key=os.getenv("GROQ_API_KEY"))

    # investigation_state = {
    # "goal": f"Analyse smart contract {address}",
    # "tools_used": [],
    # "evidence": [],
    # "observations": []
    # }

    # Groq uses system message inside messages list
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Analyse this smart contract for security exploits: {address}"}
    ]

    print(f"\nAgent starting analysis on: {address}\n")

    step = 0
    MAX_STEPS = 10

    while step < MAX_STEPS:
        step += 1
        print(f"── Step {step} ──────────────")
        print("Before API call")

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=1000,
            temperature=0,
            tools=GROQ_TOOLS,
            tool_choice="auto",
            messages=messages
        )

        print("After API call")

        message = response.choices[0].message
        finish_reason = response.choices[0].finish_reason
        print(f"finish_reason: {finish_reason}")

        # Case 1 — model is done
        if finish_reason == "stop":
            print("\n✓ Analysis complete.\n")
            return {"status": "success", "report": message.content}

        # Case 2 — model wants to call a tool
        if finish_reason == "tool_calls":
            # Add model response to history
            messages.append({
                "role": "assistant",
                "content": message.content,
                "tool_calls": message.tool_calls
            })

            # Run each tool
            for tool_call in message.tool_calls:
                tool_name = tool_call.function.name
                tool_input = json.loads(tool_call.function.arguments)

                print(f"  → calling: {tool_name}")
                print(f"  → inputs:  {tool_input}")

                tool_fn = TOOL_MAP[tool_name]
                result = tool_fn(tool_input)

                print(f"  → result:  {result}\n")

                # Feed result back
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result)
                })
                # investigation_state["tools_used"].append(tool_name)
                # investigation_state["evidence"].append(result)

    return {"status": "error", "report": "Agent hit maximum steps. Analysis incomplete."}