from fastapi import FastAPI, Depends, HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
import uvicorn
import os

app = FastAPI(title="OpenPlaneTracker Remote Ingest Server")

ADMIN_TOKEN = os.getenv("OPT_ADMIN_TOKEN", "default-admin-token")
# If mounted via config volume from sentinel, read it
if os.path.exists("/config/admin_token.txt"):
    with open("/config/admin_token.txt", "r") as f:
        ADMIN_TOKEN = f.read().strip()

API_KEY = os.getenv("OPT_SERVER_API_KEY", "default-secure-key-change-me")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
admin_token_header = APIKeyHeader(name="X-Admin-Token", auto_error=False)

def get_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Forbidden: Invalid or missing API Key"
        )
    return api_key

def get_admin_token(admin_token: str = Security(admin_token_header)):
    if admin_token != ADMIN_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Forbidden: Invalid Admin Token"
        )
    return admin_token

@app.get("/")
async def health_check():
    return {"status": "ok", "message": "Remote Ingest Server is running."}

@app.post("/api/ingest")
async def ingest_sdr_data(payload: dict, api_key: str = Depends(get_api_key)):
    """
    Endpoint for remote SDRs to push their data.
    Requires 'X-API-Key' header.
    """
    return {"status": "success", "message": "Data ingested"}

class AdminCommand(BaseModel):
    command: str
    args: dict = {}

@app.post("/api/admin/command")
async def admin_control(command: AdminCommand, admin_token: str = Depends(get_admin_token)):
    """
    Endpoint for Sentinel container to control data operations on the server.
    Requires 'X-Admin-Token' header.
    """
    cmd = command.command
    # Execute commands based on sentinel instructions
    return {"status": "success", "message": f"Executed {cmd} via admin token."}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080)
