import logging
import shlex
import asyncio
from typing import AsyncGenerator
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
import docker
from docker.errors import NotFound, APIError

# --- Configuration & Setup ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("OSINT-Bridge")

app = FastAPI(
    title="OSINT Docker Bridge",
    description="Middleware API connecting Web UI to Dockerized OSINT tools.",
    version="1.0.0"
)

# Enable CORS (Cross-Origin Resource Sharing)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins (dev mode)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration for the target container
TARGET_CONTAINER_NAME = "hexstrike-secure"

try:
    docker_client = docker.from_env()
except Exception as e:
    logger.error(f"Failed to initialize Docker client: {e}")
    docker_client = None

# --- Data Models ---

class SherlockRequest(BaseModel):
    username: str = Field(..., description="The username to search for across social networks.", min_length=1)
    
class TheHarvesterRequest(BaseModel):
    domain: str = Field(..., description="The target domain to scan (e.g., example.com).", min_length=3)
    limit: int = Field(500, description="Limit the number of results.", ge=50, le=2000)
    source: str = Field("all", description="Data source (e.g., google, bing, all).")

class GenericCommandRequest(BaseModel):
    # USE WITH CAUTION: Only for trusted internal use or rigorously sanitized inputs if exposed
    tool: str
    args: list[str]

# --- Helper Functions ---

def get_container(container_name: str):
    """Retrieves the Docker container object by name."""
    if not docker_client:
        raise HTTPException(status_code=500, detail="Docker client not initialized.")
    try:
        return docker_client.containers.get(container_name)
    except NotFound:
        raise HTTPException(status_code=404, detail=f"Container '{container_name}' not found. Is it running?")
    except APIError as e:
        raise HTTPException(status_code=500, detail=f"Docker API Error: {str(e)}")

def sanitize_arg(arg: str) -> str:
    """Sanitizes a single command line argument to prevent injection."""
    # shlex.quote creates a shell-escaped string version of the argument
    return shlex.quote(arg)

async def stream_docker_command(container, command: list[str]) -> AsyncGenerator[str, None]:
    """
    Executes a command inside the container and streams the output (stdout/stderr).
    Ref: Uses exec_run with stream=True. 
    Note: 'docker-py' exec_run stream yields bytes.
    """
    safe_command = " ".join(command)  # Arguments already sanitized before forming this list
    logger.info(f"Executing in {container.name}: {safe_command}")

    try:
        # exec_run returns (exit_code, output_generator)
        # However, with stream=True, it returns a generator that yields output
        # To get exit code AND stream is tricky in docker-py strictly synchronously, 
        # but for streaming logs we iterate the generator.
        exec_id = docker_client.api.exec_create(container.id, safe_command, stdout=True, stderr=True)
        output_stream = docker_client.api.exec_start(exec_id['Id'], stream=True)

        for chunk in output_stream:
            # Clean and yield text
            decoded_chunk = chunk.decode('utf-8', errors='replace')
            yield decoded_chunk
            # Optional: Add small sleep if needed to prevent CPU hogging in tight loops, 
            # though stream is usually blocking/waiting for I/O.
            await asyncio.sleep(0)  
            
    except Exception as e:
        yield f"ERROR: Failed to execute command: {str(e)}"

# --- Endpoints ---

@app.get("/health")
def health_check():
    """Checks if the bridge can connect to Docker and the target container."""
    status = {"docker_client": "connected" if docker_client else "disconnected"}
    try:
        container = get_container(TARGET_CONTAINER_NAME)
        status["target_container"] = "running" if container.status == "running" else container.status
    except HTTPException as e:
        status["target_container"] = "not_found"
    return status

@app.post("/scan/sherlock")
async def scan_sherlock(request: SherlockRequest):
    """
    Runs Sherlock against a username.
    """
    container = get_container(TARGET_CONTAINER_NAME)
    
    # Construct Safe Command
    # Assuming 'sherlock' is in PATH. Adjust if specific path needed (e.g. /opt/sherlock/sherlock.py)
    cmd = ["sherlock", sanitize_arg(request.username), "--timeout", "5", "--print-all"]
    
    return StreamingResponse(
        stream_docker_command(container, cmd),
        media_type="text/plain"
    )

@app.post("/scan/theharvester")
async def scan_theharvester(request: TheHarvesterRequest):
    """
    Runs TheHarvester against a domain.
    """
    container = get_container(TARGET_CONTAINER_NAME)
    
    # Construct Safe Command
    cmd = [
        "theHarvester", 
        "-d", sanitize_arg(request.domain), 
        "-b", sanitize_arg(request.source), 
        "-l", str(request.limit) 
        # Note: Integers like 'limit' are safe, but casting to str for list join
    ]
    
    return StreamingResponse(
        stream_docker_command(container, cmd),
        media_type="text/plain"
    )

if __name__ == "__main__":
    import uvicorn
    # Run the API server
    uvicorn.run(app, host="0.0.0.0", port=8000)
