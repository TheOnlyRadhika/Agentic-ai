# test_env.py
from dotenv import load_dotenv
import os

load_dotenv()

print("Etherscan:", os.getenv("ETHERSCAN_API_KEY"))
print("Anthropic:", os.getenv("ANTHROPIC_API_KEY"))
print("Groq:", os.getenv("GROQ_API_KEY"))