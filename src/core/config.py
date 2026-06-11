"""
Lab 11 — Configuration & API Key Setup
"""
import os

# LLM backend configuration (Fireworks AI endpoint)
LLM_MODEL = os.environ.get("LLM_MODEL", "accounts/fireworks/models/deepseek-v4-flash")
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "https://api.fireworks.ai/inference/v1")


def setup_api_key():
    """Load LLM API key from environment or prompt, then configure LiteLLM."""
    if "LLM_API_KEY" not in os.environ or not os.environ["LLM_API_KEY"]:
        os.environ["LLM_API_KEY"] = input("Enter LLM API Key: ")

    # Forward to OPENAI_API_KEY so LiteLLM (used by Google ADK) picks it up
    os.environ["OPENAI_API_KEY"] = os.environ["LLM_API_KEY"]
    os.environ["OPENAI_API_BASE"] = LLM_BASE_URL
    print("API key loaded.")


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
