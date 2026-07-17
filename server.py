from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agent import run_agent

app = FastAPI(
    title="Agentic AI Smart Contract Scanner",
    description="Autonomous AI-powered smart contract investigation agent",
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
class AnalyseRequest(BaseModel):
    address: str

@app.get("/")
def home():
    return {"message": "Server is running!"}

@app.post("/analyse")
def analyse(request: AnalyseRequest):
    result = run_agent(request.address)
    return result