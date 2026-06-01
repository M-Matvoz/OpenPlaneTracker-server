from fastapi import FastAPI, Depends, HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
import uvicorn
import os
import asyncio
import json
from datetime import datetime
from pathlib import Path
import httpx
import asyncio

app = FastAPI(title="OpenPlaneTracker Remote Ingest Server")

# Tokens and simple auth
ADMIN_TOKEN = os.getenv("OPT_ADMIN_TOKEN", "default-admin-token")
if os.path.exists("/config/admin_token.txt"):
    with open("/config/admin_token.txt", "r") as f:
        ADMIN_TOKEN = f.read().strip()

API_KEY = os.getenv("OPT_SERVER_API_KEY", "default-secure-key-change-me")
SHARED_PSK = os.getenv("OPT_SHARED_PSK", "default-shared-psk")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
admin_token_header = APIKeyHeader(name="X-Admin-Token", auto_error=False)
psk_header = APIKeyHeader(name="X-PSK", auto_error=False)

EXTERNAL_CONNECTIONS_ENABLED = False
REGISTERED_PEERS: dict[str, dict] = {}
OUTGOING_PUSH_CONFIG = {
    "enabled": False,
    "target_url": None,
    "interval_seconds": 2,
}

# In-memory cache for aircraft data
aircraft_data_cache = {
    "now": 0,
    "messages": 0,
    "aircraft": [],
}

# List of registered SDR sources
sdr_sources = []


def get_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Forbidden: Invalid or missing API Key")
    return api_key


def get_admin_token(admin_token: str = Security(admin_token_header)):
    if admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Forbidden: Invalid Admin Token")
    return admin_token


# Data storage paths
DATA_DIR = Path(os.getenv("OPT_DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
INGEST_FILE = DATA_DIR / "ingested.json"
COLLATED_FILE = DATA_DIR / "collated.json"


@app.get("/")
async def health_check():
    return {"status": "ok", "message": "Remote Ingest Server is running."}


@app.post("/api/ingest")
async def ingest_sdr_data(
    payload: dict,
    api_key: str = Security(api_key_header),
    psk: str = Security(psk_header),
):
    """
    Endpoint for remote SDRs to push their data.
    Requires 'X-API-Key' or shared 'X-PSK' header.
    Data is appended to a local ingested file for later collation.
    """
    if not EXTERNAL_CONNECTIONS_ENABLED:
        raise HTTPException(status_code=403, detail="External connections are disabled")

    if api_key != API_KEY and psk != SHARED_PSK:
        raise HTTPException(status_code=401, detail="Forbidden: Invalid API Key or shared peer key")

    entry = {"timestamp": datetime.utcnow().isoformat() + "Z", "payload": payload}

    # load existing
    try:
        if INGEST_FILE.exists():
            with INGEST_FILE.open("r", encoding="utf-8") as f:
                lst = json.load(f)
        else:
            lst = []
    except Exception:
        lst = []

    lst.append(entry)
    try:
        with INGEST_FILE.open("w", encoding="utf-8") as f:
            json.dump(lst, f)
    except Exception:
        pass

    return {"status": "success", "message": "Data ingested"}


class AdminCommand(BaseModel):
    command: str
    args: dict = {}


class ExternalConnectionsToggle(BaseModel):
    enabled: bool = True


class PeerRegistration(BaseModel):
    peer_name: str
    peer_url: str | None = None
    shared_key: str | None = None


class PushConfig(BaseModel):
    target_url: str
    enabled: bool = True
    interval_seconds: int = 2
    shared_key: str | None = None


class SDRSource(BaseModel):
    name: str
    url: str


@app.post("/api/admin/command")
async def admin_control(command: AdminCommand, admin_token: str = Depends(get_admin_token)):
    """
    Endpoint for Sentinel container to control data operations on the server.
    Requires 'X-Admin-Token' header.
    Supported commands: 'collate_now' to refresh the collated file immediately.
    """
    cmd = command.command
    if cmd == "collate_now":
        await collate_and_write()
        return {"status": "success", "message": "Collated now"}
    return {"status": "success", "message": f"Executed {cmd} via admin token."}


@app.get("/admin/state")
async def admin_state(admin_token: str = Depends(get_admin_token)):
    return {
        "external_connections_enabled": EXTERNAL_CONNECTIONS_ENABLED,
        "registered_peers": list(REGISTERED_PEERS.values()),
        "push_config": OUTGOING_PUSH_CONFIG,
        "shared_key": SHARED_PSK,
    }


@app.post("/admin/external-connections/enable")
async def admin_enable_external_connections(
    cfg: ExternalConnectionsToggle, admin_token: str = Depends(get_admin_token)
):
    global EXTERNAL_CONNECTIONS_ENABLED, OUTGOING_PUSH_CONFIG
    EXTERNAL_CONNECTIONS_ENABLED = cfg.enabled
    # If enabling receive, disable push (mutually exclusive)
    if cfg.enabled:
        OUTGOING_PUSH_CONFIG["enabled"] = False
    return {"status": "success", "external_connections_enabled": EXTERNAL_CONNECTIONS_ENABLED}


@app.post("/admin/push-config")
async def admin_configure_push(cfg: PushConfig, admin_token: str = Depends(get_admin_token)):
    global OUTGOING_PUSH_CONFIG, EXTERNAL_CONNECTIONS_ENABLED
    key = cfg.shared_key or SHARED_PSK
    if key != SHARED_PSK:
        raise HTTPException(status_code=403, detail="Invalid shared key")

    OUTGOING_PUSH_CONFIG["enabled"] = cfg.enabled
    OUTGOING_PUSH_CONFIG["target_url"] = cfg.target_url
    OUTGOING_PUSH_CONFIG["interval_seconds"] = max(2, int(cfg.interval_seconds or 2))
    # If enabling push, disable receive (mutually exclusive)
    if cfg.enabled:
        EXTERNAL_CONNECTIONS_ENABLED = False
    return {"status": "success", "push_config": OUTGOING_PUSH_CONFIG}


async def fetch_sdr_sources_from_sentinel():
    """Periodically fetch the list of available SDRs from the Sentinel container."""
    sentinel_url = os.getenv("OPT_SENTINEL_URL", "http://sentinel:8001/api/sdrs")
    async with httpx.AsyncClient() as client:
        while True:
            try:
                r = await client.get(sentinel_url, timeout=10)
                if r.status_code == 200:
                    global sdr_sources
                    sdr_sources = r.json()
            except Exception as e:
                print(f"Error fetching SDR sources from Sentinel: {e}")
            await asyncio.sleep(20)


@app.post("/admin/sdr-sources")
async def admin_add_sdr_source(source: SDRSource, admin_token: str = Depends(get_admin_token)):
    """Add or update an SDR source."""
    global sdr_sources
    # Remove existing source with the same name
    sdr_sources = [s for s in sdr_sources if s["name"] != source.name]
    sdr_sources.append({"name": source.name, "url": source.url})
    return {"status": "success", "sdr_sources": sdr_sources}


@app.delete("/admin/sdr-sources/{name}")
async def admin_delete_sdr_source(name: str, admin_token: str = Depends(get_admin_token)):
    """Delete an SDR source."""
    global sdr_sources
    sdr_sources = [s for s in sdr_sources if s["name"] != name]
    return {"status": "success", "sdr_sources": sdr_sources}


async def fetch_url(client: httpx.AsyncClient, url: str, headers: dict | None = None):
    try:
        r = await client.get(url, timeout=5.0, headers=headers)
        if r.status_code == 200 and r.text.strip():
            return r.json()
    except Exception:
        return None


async def collate_sources() -> dict:
    """Collect data from local ingests, configured SDR URLs and external URLs.
    Returns a dict with a single top-level 'aircraft' array for compatibility with UI.
    """
    # local ingested
    local_list = []
    try:
        if INGEST_FILE.exists():
            with INGEST_FILE.open("r", encoding="utf-8") as f:
                local_list = json.load(f)
    except Exception:
        local_list = []

    # Prepare URLs from env
    sdr_urls = [u.strip() for u in os.getenv("OPT_SDR_URLS", "").split(",") if u.strip()]
    external_urls = [u.strip() for u in os.getenv("OPT_EXTERNAL_URLS", "").split(",") if u.strip()]

    # Add dynamically registered SDR sources
    sdr_urls.extend([s["url"] for s in sdr_sources])

    collected_aircraft = []

    # local entries might already contain airplane lists under payload['aircraft']
    for e in local_list:
        try:
            p = e.get("payload", {})
            if isinstance(p, dict) and "aircraft" in p and isinstance(p["aircraft"], list):
                collected_aircraft.extend(p["aircraft"])
        except Exception:
            continue

    headers = {"X-API-Key": API_KEY}
    async with httpx.AsyncClient() as client:
        tasks = []
        for u in sdr_urls + external_urls:
            tasks.append(fetch_url(client, u, headers=headers))

        results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in results:
        if isinstance(res, dict) and "aircraft" in res and isinstance(res["aircraft"], list):
            collected_aircraft.extend(res["aircraft"])  # merge lists

    # Final shape matching the requested format: { now, messages, aircraft }
    out = {
        "now": float(datetime.utcnow().timestamp()),
        "messages": len(collected_aircraft),
        "aircraft": collected_aircraft,
    }
    return out


async def collate_and_write():
    data = await collate_sources()
    try:
        with COLLATED_FILE.open("w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass
    return data


async def push_collated_once(target_url: str):
    data = await collate_sources()
    headers = {"X-PSK": SHARED_PSK, "Content-Type": "application/json"}
    async with httpx.AsyncClient() as client:
        await client.post(target_url, json=data, headers=headers, timeout=5.0)


@app.get("/api/collated")
async def get_collated():
    """Return collated JSON (and update the on-disk collated file)."""
    return aircraft_data_cache


@app.on_event("startup")
async def startup_tasks():
    # Start the background task to fetch SDR sources from Sentinel
    asyncio.create_task(fetch_sdr_sources_from_sentinel())

    # Optionally run a periodic collate in background if OPT_AUTOCOLLATE is set
    if os.getenv("OPT_AUTOCOLLATE", "1") == "1":

        async def periodic():
            while True:
                try:
                    global aircraft_data_cache
                    aircraft_data_cache = await collate_and_write()
                except Exception:
                    pass
                await asyncio.sleep(2)

        asyncio.create_task(periodic())

    async def push_periodic():
        while True:
            try:
                if OUTGOING_PUSH_CONFIG["enabled"] and OUTGOING_PUSH_CONFIG["target_url"]:
                    await push_collated_once(OUTGOING_PUSH_CONFIG["target_url"])
                    await asyncio.sleep(int(OUTGOING_PUSH_CONFIG["interval_seconds"]))
                else:
                    await asyncio.sleep(2)
            except Exception:
                await asyncio.sleep(2)

    asyncio.create_task(push_periodic())


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080)
