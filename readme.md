# 🛡️ Agentic AI Smart Contract Security Scanner

An autonomous AI-powered security analyst for Ethereum smart contracts. The agent investigates a deployed contract using a ReAct reasoning loop, performs both dynamic and static analysis, retrieves relevant security knowledge through Retrieval-Augmented Generation (RAG), maintains short-term reasoning memory, and generates a professional security audit report.

---

## 🚀 Features

### 🤖 Agentic Investigation (ReAct)
- Uses an LLM-based planner to determine the next investigation step.
- Dynamically selects tools based on the current investigation state.
- Prevents redundant tool execution using tool call history.
- Stops automatically when sufficient evidence has been collected.

---

### 🔍 Dynamic Transaction Analysis
Retrieves historical transactions from Etherscan and detects suspicious patterns including:
- Reentrancy-like transaction behavior
- Large balance drain patterns
- First-time sender anomalies

---

### 📄 Static Source Code Analysis
Fetches verified Solidity source code from Etherscan and performs heuristic security analysis.

Current checks include:
- delegatecall usage
- Low-level external calls
- tx.origin authentication
- selfdestruct capability
- Inline assembly

---

### 🧠 Short-Term Memory
The agent maintains an internal working memory throughout the investigation.

Instead of only storing raw tool outputs, a dedicated LLM reflection module summarizes each investigation step into:

- Observation
- Decision

This allows the planner to reason using previous conclusions rather than repeatedly analyzing raw evidence.

---

### 📚 Retrieval-Augmented Generation (RAG)
The report generator retrieves relevant security knowledge from a local Markdown knowledge base.

Examples include:
- delegatecall
- reentrancy
- tx.origin
- assembly
- selfdestruct
- access control
- fund drain attacks

Retrieved knowledge is supplied to the report generation model to provide:
- Better explanations
- Risk analysis
- Security recommendations
- Mitigation strategies

---

### 📊 Professional Audit Report
Generates a structured audit report containing:

- Executive Summary
- Risk Score
- Confidence Score
- Security Findings
- Supporting Evidence
- Investigation Limitations
- Recommended Mitigations

---

## 🏗️ Architecture

```text
                User Contract Address
                         │
                         ▼
               ReAct Planner (LLM)
                         │
        ┌────────────────┴────────────────┐
        ▼                                 ▼
 Transaction Analysis             Source Code Retrieval
        │                                 │
        ▼                                 ▼
 Dynamic Pattern Detection        Static Source Analysis
        │                                 │
        └──────────────┬──────────────────┘
                       ▼
              Investigation State
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
  Short-Term Memory              RAG Retriever
         │                           │
         └─────────────┬─────────────┘
                       ▼
              Report Generation LLM
                       │
                       ▼
         Professional Security Report
```

---

## 📂 Project Structure

```text
Agentic-ai/

├── agent.py                  # ReAct agent implementation
├── tools.py                  # Investigation tools
├── context.py                # LLM prompts
├── server.py                 # Flask API
├── test_agent.py             # CLI interface
├── knowledge_base/
│   ├── delegatecall.md
│   ├── reentrancy.md
│   ├── assembly.md
│   ├── tx_origin.md
│   ├── selfdestruct.md
│   ├── access_control.md
│   ├── fund_drain.md
│   └── new_wallet_attack.md
├── requirements.txt
└── README.md
```

---

## ⚙️ Tech Stack

### AI
- Groq API
- Llama 3.3 70B

### Blockchain
- Ethereum
- Etherscan API

### Backend
- Python
- Flask

### Libraries
- requests
- python-dotenv
- json

---

## 🛠️ Installation

Clone the repository

```bash
git clone <repository-url>

cd Agentic-ai
```


Install dependencies

```bash
uv sync
```

Create a `.env` file

```env
GROQ_API_KEY=YOUR_GROQ_API_KEY
ETHERSCAN_API_KEY=YOUR_ETHERSCAN_API_KEY
```

---

## ▶️ Running the Agent

Command Line

```bash
python test_agent.py
```

API Server

```bash
uv run uvicorn server:app --reload
```


## 🔄 Investigation Pipeline

```text
Receive Contract Address
        │
        ▼
Fetch Transactions
        │
        ▼
Dynamic Pattern Analysis
        │
        ▼
Retrieve Verified Source Code
        │
        ▼
Static Source Analysis
        │
        ▼
Update Short-Term Memory
        │
        ▼
Retrieve Relevant Security Knowledge
        │
        ▼
Generate Professional Security Report
```

---

## 🧠 Agent Design

The project follows a ReAct (Reasoning + Acting) architecture.

During every investigation cycle the planner:

1. Observes current investigation state
2. Reads previous reasoning from short-term memory
3. Selects the most appropriate investigation tool
4. Executes the tool
5. Reflects on the results
6. Updates memory
7. Continues until sufficient evidence has been gathered

This creates a stateful investigation workflow instead of a single-pass LLM interaction.

---

## 📈 Future Improvements

- Vector database-based semantic RAG
- Symbolic execution
- Slither integration
- Mythril integration
- Multi-chain support
- Access control graph analysis
- Function-level vulnerability detection
- Interactive React frontend
- Docker deployment

---

## 📄 License

MIT License

---
