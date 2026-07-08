from agent import run_agent

print("=== Smart Contract Security Scanner ===")

address = input("Enter Ethereum Contract Address: ").strip()

print("\nStarting analysis...\n")

result = run_agent(address)

print("\n========== FINAL REPORT ==========")
print(result)