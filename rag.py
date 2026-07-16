import os
KNOWLEDGE_DIR = "knowledge_base"

def retrieve_context(investigation_state):
    retrieved_docs = set()

    source_findings = investigation_state.get("source_findings", {})
    for finding in source_findings.get("findings", []):
        retrieved_docs.add(finding["type"] + ".md")

    dynamic_findings = investigation_state.get("full_findings", {})
    if dynamic_findings.get("reentrancy_flags"):
        retrieved_docs.add("reentrancy.md")
    if dynamic_findings.get("balance_drains"):
        retrieved_docs.add("fund_drain.md")
    if dynamic_findings.get("first_time_sender_flags"):
        retrieved_docs.add("new_wallet_attack.md")

    retrieved_context = []
    for finding in source_findings.get("findings" , []):
        filename = finding["type"]+ ".md"
        filepath = os.path.join(KNOWLEDGE_DIR, filename)
        if os.path.exists(filepath):
            with open(filepath, 'r') as file:
                content = file.read()
                retrieved_context.append(content)

    return "\n\n".join(retrieved_context)






if __name__ == "__main__":

    source_findings = {
        "findings": [
            {"type": "delegatecall"},
            {"type": "tx_origin"}
        ]
    }

    retrieve_context(source_findings)