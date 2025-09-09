import os
from dotenv import load_dotenv

load_dotenv()
print("VT_API_KEY:", os.getenv("VT_API_KEY"))
