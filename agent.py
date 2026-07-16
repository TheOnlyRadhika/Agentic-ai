import os
import json
from unittest import result
from groq import Groq
from tools import TOOL_MAP, TOOL_DEFINITIONS, analyse_source_code
from dotenv import load_dotenv
from rag import retrieve_context


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
        Your primary objective is to determine whether a smart contract 
            shows evidence of vulnerabilities, exploitation, or suspicious behaviour.
        You are an investigator, not a report generator.

        -------------------------
        INVESTIGATION STRATEGY
        -------------------------
       Before every tool call, reason through the following questions:
        1. What evidence do I already have?
        2. What important evidence is still missing?
        3. Which available tool will reduce that uncertainty the most?
        4. Will this new evidence materially improve the investigation?
        Only call a tool if it provides new information.
        Avoid repeating tool calls that have already been completed successfully.
        Do not continue investigating if sufficient evidence has already been collected
            to support a conclusion.
        If both transaction analysis and source-code analysis are available, combine 
            evidence from both before producing a final report.
        
        -------------------------
        INVESTIGATION PRIORITIES
        -------------------------
        Prefer collecting evidence in the following order:
        1. Transaction history
        2. Transaction pattern analysis
        3. Verified source code
        4. Static source-code analysis
        Only proceed to the next stage if the previous evidence is insufficient 
          for a confident conclusion.
        If no verified source code exists, explain that this limits the   
           investigation rather than repeatedly attempting to retrieve it.

        -------------------------
        REASONING PRINCIPLES
        -------------------------
        Base every conclusion on evidence returned by tools.
        Never fabricate blockchain data.
        Never assume that the absence of evidence proves that the contract is safe.
        If evidence is insufficient, clearly explain what information is missing.
        If multiple independent pieces of evidence point toward the same attack pattern, 
        increase confidence in your conclusion.

        You will receive:

        1. Investigation Summary
        2. Background Security Knowledge

        The Investigation Summary contains the evidence collected by the investigation.
        The Background Security Knowledge contains general smart contract security guidance.
        Never treat the background knowledge as evidence.

        Use it only to:
        - explain why a finding is risky,
        - recommend mitigations,
        - improve the quality of the report.
    """

REPORT_PROMPT = """
            You are a senior Ethereum Smart Contract Security Auditor.
            You are NOT responsible for investigating the contract.
            The investigation has already been completed.
            You will receive a structured investigation summary.
            Your job is to convert the investigation summary into a professional security report.

            Rules:
            - Use ONLY the evidence provided.
            - Never invent vulnerabilities.
            - Explain findings clearly.
            - Mention investigation limitations if present.

            Produce the report using this format:
            # Executive Summary
            # Risk Score (1-10)
            # Confidence Score (0-100%)
            # Security Findings
            # Evidence
            # Investigation Limitations
            # Recommended Next Steps

            REPORT STYLE RULES:
            - Keep the report concise and easy to scan.
            - Do not use long paragraphs when a short statement is sufficient.
            - Clearly distinguish confirmed vulnerabilities, suspicious signals, and weak heuristics.
            - A first-time sender alone must not be treated as evidence of an attack.
            - Use short sections and concise bullet points.
            - Include only the most relevant evidence.
            - Do not repeat the same finding in multiple sections.
            - Risk scores must reflect evidence strength:
            1-2: No meaningful evidence of exploitation
            3-4: Weak suspicious signals
            5-6: Multiple concerning indicators
            7-8: Strong evidence of vulnerability or exploitation
            9-10: Confirmed or near-certain active exploitation
                 Your goal is not to call every available tool.
                 Your goal is to gather enough evidence to make the best possible security assessment
            """

MEMORY_PROMPT = """
        You are the short-term memory module of an autonomous smart contract security agent.
        Your job is to summarize the latest tool execution.
        Given the tool name and a compact summary of its result, generate:
        1. Observation:
        - What was learned from this tool execution?
        2. Decision:
        - What should the agent investigate next based on this result?
        Rules:
        - Keep each response to one concise sentence.
        - Do not repeat raw JSON.
        - Do not invent facts.
        - Base your reasoning only on the provided tool summary.
        - Return ONLY valid JSON in the following format:
        {
            "observation": "...",
            "decision": "..."
        }
        """


def build_planner_context(investigation_state):

            planner_context = f"""
            CURRENT INVESTIGATION STATE
            Goal:
            {investigation_state["goal"]}
            Transaction History Collected:
            {"Yes" if investigation_state["raw_transactions"] else "No"}
            Transaction Analysis Completed:
            {"Yes" if investigation_state["transaction_findings"] else "No"}
            Verified Source Code Available:
            {"Yes" if investigation_state["source_code"] else "No"}
            Static Source Analysis Completed:
            {"Yes" if investigation_state["source_findings"] else "No"}
            Completed Investigation Steps:
            {", ".join(investigation_state["tools_used"]) if investigation_state["tools_used"] else "None"}
            Use this information before deciding the next investigative action.
            Do not repeat completed investigation steps unless new evidence requires it.
            """
            memory_summary = build_memory_summary(investigation_state)
            planner_context += f"""
                =========================
                SHORT-TERM MEMORY
                =========================
                {memory_summary if memory_summary else "No previous reasoning available."}
                Use this memory to:
                - Avoid repeating completed investigations.
                - Build upon previous observations.
                - Decide the next best investigative action.
                """
            return planner_context



def build_investigation_summary(investigation_state):
    summary = []
    summary.append("=== INVESTIGATION SUMMARY ===")
    transaction_findings = investigation_state.get("transaction_findings", {})
    summary.append("")
    summary.append("Dynamic Analysis")
    summary.append("----------------")
    summary.append(
    f"Transactions Scanned: {transaction_findings.get('transactions_scanned', 0)}")
    summary.append(
        f"Reentrancy Flags: {len(transaction_findings.get('reentrancy_flags', []))}")
    summary.append(
        f"Balance Drains: {len(transaction_findings.get('balance_drains', []))}")
    summary.append(
        f"First-Time Senders: {len(transaction_findings.get('first_time_sender_flags', []))}")
    
    source_findings = investigation_state.get("source_findings", {})
    summary.append("")
    summary.append("Static Analysis")
    summary.append("----------------")
    summary.append(
        f"Vulnerabilities Found: {len(source_findings.get('vulnerabilities', []))}"
    )
    source_findings = investigation_state.get("source_findings", {})

    summary.append("")
    summary.append("Static Analysis")
    summary.append("----------------")

    summary.append(
        f"Total Static Findings: {source_findings.get('total_findings', 0)}"
    )
    for finding in source_findings.get("findings", []):
        summary.append(
            f"- [{finding['severity']}] {finding['type']}"
        )

    summary.append("")
    summary.append("Overall Investigation")
    summary.append("----------------------")
    dynamic = investigation_state.get("transaction_findings", {})
    static = investigation_state.get("source_findings", {})
    total = (
        dynamic.get("total_suspicious_patterns", 0)
        + static.get("total_findings", 0)
    )
    summary.append(f"Total Indicators Detected: {total}")
    summary.append(
    f"Dynamic Analysis Completed: {'Yes' if dynamic else 'No'}")
    summary.append(
        f"Static Analysis Completed: {'Yes' if static else 'No'}"
    )
    return "\n".join(summary)



def generate_final_report(client, investigation_state):
    summary = build_investigation_summary(investigation_state)
    rag_context =retrieve_context(investigation_state)

    user_prompt = f"""
        ========================
        INVESTIGATION SUMMARY
        ========================

        {summary}

        ========================
        BACKGROUND SECURITY KNOWLEDGE
        ========================

        {rag_context}

        The background security knowledge is background information only.
        Do NOT treat it as evidence.

        Generate the final audit report using the investigation summary as evidence,
        and use the background knowledge only to explain risks and recommend mitigations.
        """
    messages = [
        {"role": "system", "content": REPORT_PROMPT},
        {"role": "user","content": user_prompt}
    ]
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",temperature=0,
        max_tokens=1000,messages=messages
    )
    return response.choices[0].message.content




def update_short_term_memory(client , investigation_state,tool_name,result):
    """
    Updates the short-term memory of the investigation state with the latest tool result.
    """
    tool_summary = {
        "tool": tool_name,
        "success" : result.get("success", False)
    }
    
    if tool_name == "get_contract_transactions":
        tool_summary["transactions"] = result.get(
            "total_fetched", 0
        )
    elif tool_name == "compute_suspicious_patterns":
        tool_summary["patterns"] = result.get(
        "total_suspicious_patterns", 0
        )
        tool_summary["pattern_types"] = {
        "reentrancy": len(result.get("reentrancy_flags", [])),
        "balance_drains": len(result.get("balance_drains", [])),
        "first_time_senders": len(result.get("first_time_sender_flags", []))
    }
    elif tool_name == "get_contract_source":
        tool_summary["verified"] = result.get("verified", False)
        tool_summary["contract_name"] = result.get("contract_name", "")

    elif tool_name == "analyse_source_code":
        tool_summary["findings"] = result.get(
            "total_findings", 0
        )


    messages = [
    {"role": "system", "content": MEMORY_PROMPT},
    {"role": "user","content": json.dumps(tool_summary)}
    ]

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        temperature=0,
        messages=messages,
        response_format={"type": "json_object"}
    )

    reflection = json.loads(
        response.choices[0].message.content
    )
    investigation_state["short_term_memory"].append({
        "step": len(investigation_state["short_term_memory"]) + 1,
        "tool": tool_name,
        "observation": reflection["observation"],
        "decision": reflection["decision"]
    })
    return reflection

def build_memory_summary(investigation_state):
    memory = investigation_state["short_term_memory"]
    summary = []
    for entry in memory[-5:]:
        summary.append(
            f"""
        Step {entry['step']}
        Observation:
        {entry['observation']}
        Decision:
        {entry['decision']}
        """
    )
    return "\n".join(summary)



def run_agent(address: str) -> dict:

    client = Groq(api_key=os.getenv("GROQ_API_KEY"))

    investigation_state = {
    "goal": f"Analyse smart contract {address}",
    "tools_used": [],
    "evidence": [],
    "observations": [],
    "raw_transactions" : [],
    "transaction_findings": {},
    "tool_call_history": [],
    "source_code" : None,
    "source_findings": {},
    "short_term_memory" : []
    }
    
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

        
        planner_context = build_planner_context(investigation_state)
        
        planner_messages = messages + [
                {"role": "user","content": planner_context}
            ]
        
        print("Before API call")
        
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=1000,
            temperature=0,
            tools=GROQ_TOOLS,
            tool_choice="auto",
            messages=planner_messages
        )

        print("After API call")
       
        message = response.choices[0].message
        finish_reason = response.choices[0].finish_reason
        print(f"finish_reason: {finish_reason}")

        # Case 1 — model is done
        if finish_reason == "stop":
            print("\n✓ Analysis complete.\n")
            final_report = generate_final_report(client,investigation_state)
            return {"status": "success", "report": final_report}

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
                print(f"  → inputs: {tool_input}")

                call_signature = {
                    "tool": tool_name,
                    "input": tool_input
                }

                if call_signature in investigation_state["tool_call_history"]:

                    llm_result = {
                        "success": False,
                        "error": "This exact tool call has already been executed. Use existing evidence or choose a different investigation strategy."
                    }

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps(llm_result)
                    })

                    continue

                investigation_state["tool_call_history"].append(call_signature)
                tool_fn = TOOL_MAP[tool_name]

                # CASE 1: Fetch transactions
                if tool_name == "get_contract_transactions":

                    result = tool_fn(tool_input)

                    if result.get("transactions") is not None:
                        investigation_state["raw_transactions"] = result["transactions"]

                        llm_result = {
                            "success": True,
                            "total_fetched": result["total_fetched"],
                            "message": "Transactions fetched successfully and stored for further analysis."
                        }
                    else:
                        llm_result = result

                # CASE 2: Analyze suspicious patterns
                elif tool_name == "compute_suspicious_patterns":

                    transactions = investigation_state["raw_transactions"]

                    if not transactions:
                        result = {
                            "success": False,
                            "error": "No transactions available. Call get_contract_transactions first."
                        }
                        llm_result = result

                    else:
                        result = tool_fn({
                            "transactions": transactions,
                            "address": tool_input["address"]
                        })

                        # Store ALL findings privately in Python state
                        investigation_state["transaction_findings"] = result

                        # Send only compact evidence to LLM
                        llm_result = {
                            "reentrancy": {
                                "count": len(result["reentrancy_flags"]),
                                "examples": result["reentrancy_flags"][:5]
                            },
                            "balance_drains": {
                                "count": len(result["balance_drains"]),
                                "examples": result["balance_drains"][:5]
                            },
                            "first_time_senders": {
                                "count": len(result["first_time_sender_flags"]),
                                "examples": result["first_time_sender_flags"][:5]
                            },
                            "total_suspicious_patterns": result["total_suspicious_patterns"],
                            "transactions_scanned": result["transactions_scanned"]
                        }
                
                elif tool_name == "get_contract_source":

                    result = tool_fn(tool_input)

                    if result.get("success") and result.get("source_code"):

                        # Store complete source code privately in Python state
                        investigation_state["source_code"] = result["source_code"]

                        # Send only compact metadata to the LLM
                        llm_result = {
                            "success": True,
                            "verified": True,
                            "contract_name": result.get("contract_name"),
                            "compiler_version": result.get("compiler_version"),
                            "source_length": len(result["source_code"]),
                            "message": "Verified source code fetched successfully and stored for further static analysis."
                        }

                    else:
                        llm_result = result


                elif tool_name == "analyse_source_code":
                    source = investigation_state.get("source_code")
                    if not source:
                        result = {
                            "success": False,
                            "error": "No source code available. Call get_contract_source first."
                        }
                        llm_result = result
                    else:
                        result = tool_fn({"source_code" : source})
                        investigation_state["source_findings"] = result

                        llm_result= {
                            "total_findings": result["total_findings"],
                            "findings": result["findings"][:5]
                            }
                        
                # CASE 3: Future tools
                else:
                    result = tool_fn(tool_input)
                    llm_result = result

                print(f"  → result for LLM: {llm_result}\n")

                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(llm_result)
                })

                investigation_state["tools_used"].append(tool_name)

                investigation_state["observations"].append({
                    "tool": tool_name,
                    "result": llm_result
                })
                update_short_term_memory(client, investigation_state, tool_name,llm_result)
                print("\nMemory Updated:")
                print(build_memory_summary(investigation_state))

    return {
        "status": "error",
        "report": "Agent hit maximum steps. Analysis incomplete."
        }