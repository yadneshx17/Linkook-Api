import subprocess
import json
import sys
import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change this in production (e.g., ["https://yourfrontend.com"])
    allow_credentials=True,
    allow_methods=["*"],  # Allows all HTTP methods
    allow_headers=["*"],  # Allows all headers
)

# API Key Setup 
API_KEY = os.getenv("API_KEY", "default-api-key")
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

def get_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

# @app.get("/linkook/{username}")
# def lookup(username: str, show_summary: bool = False, api_key: str = Depends(get_api_key)):
#     """
#     Executes the Linkook tool using:
#         linkook {username}
#     Optionally appends the --show-summary flag.
#     """
#     try:
#         # Construct the command
#         command = ["linkook", username]
#         if show_summary:
#             command.append("--show-summary")
        
#         # Run the command and capture output
#         result = subprocess.run(command, capture_output=True, text=True)
        
#         if result.returncode != 0:
#             raise HTTPException(status_code=500, detail=f"Error: {result.stderr.strip()}")
        
#         # Parse JSON output (assuming Linkook outputs JSON)
#         output = json.loads(result.stdout.strip())
#         return output
#     except json.JSONDecodeError:
#         raise HTTPException(status_code=500, detail="Failed to parse JSON output from Linkook.")
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

# @app.get("/linkook/{username}")
# def lookup(username: str, show_summary: bool = False, api_key: str = Depends(get_api_key)):
#     """
#     Executes the Linkook tool using:
#         linkook {username}
#     Optionally appends the --show-summary flag.
#     """
#     try:
#         # Construct the command
#         command = ["linkook", username]
#         if show_summary:
#             command.append("--show-summary")

#         # Run the command and capture output
#         result = subprocess.run(command, capture_output=True, text=True)

#         if result.returncode != 0:
#             raise HTTPException(status_code=500, detail=f"Error: {result.stderr.strip()}")

#         # Try to parse JSON output
#         try:
#             output = json.loads(result.stdout.strip())
#             return output
#         except json.JSONDecodeError:
#             return {
#                 "raw_output": result.stdout.strip(),
#                 "error": "Output from Linkook is not valid JSON. Here's the raw output."
#             }

#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

@app.get("/linkook/{username}")
def lookup(username: str, show_summary: bool = False, api_key: str = Depends(get_api_key)):
    """
    Executes the Linkook tool using:
        linkook {username}
    Optionally appends the --show-summary flag.
    The function attempts to parse the output as JSON.
    If parsing fails, it wraps the raw output in a JSON response.
    """
    try:
        # Construct the command without a JSON flag
        command = ["linkook", username]
        if show_summary:
            command.append("--show-summary")
        
        # Run the command and capture output
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Error: {result.stderr.strip()}"
            )
        
        raw_output = result.stdout.strip()
        
        # Attempt to parse the raw output as JSON
        try:
            output = json.loads(raw_output)
            return output
        except json.JSONDecodeError:
            # If output isn't valid JSON, return it as a string in a JSON object
            return {"raw_output": raw_output, "error": "Output is not valid JSON"}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))