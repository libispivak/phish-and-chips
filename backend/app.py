"""HTTP API for the Gmail add-on.

POST /analyze  {"raw_base64": "<the full email, base64>"}  -> score, verdict, reasons
GET  /health                                               -> {"status": "ok"}

Security choices:
- Every /analyze call must carry the shared secret in the X-API-Key header.
  The secret comes from an environment variable, never from the code.
- Requests larger than MAX_REQUEST_BYTES are rejected before being read.
- Email content is never logged or stored; we only log the verdict.
"""

import base64
import binascii
import hmac
import logging
import os

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from scorer.engine import score_email
from scorer.parser import MAX_MESSAGE_BYTES, MessageTooLarge

API_KEY = os.environ.get("SCORER_API_KEY", "")
if len(API_KEY) < 32:
    raise RuntimeError("Set SCORER_API_KEY to a random secret of at least 32 characters.")

MAX_REQUEST_BYTES = MAX_MESSAGE_BYTES * 4 // 3 + 1024   # base64 makes data ~33% bigger

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("scorer")

app = FastAPI(title="Phish & Chips", docs_url=None, redoc_url=None, openapi_url=None)


class AnalyzeRequest(BaseModel):
    raw_base64: str


@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    length = request.headers.get("content-length")
    if length is None and request.method == "POST":
        return JSONResponse({"error": "Content-Length required"}, status_code=411)
    if length is not None and (not length.isdigit() or int(length) > MAX_REQUEST_BYTES):
        return JSONResponse({"error": "Email is too large to analyze"}, status_code=413)
    return await call_next(request)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(body: AnalyzeRequest, x_api_key: str = Header(default="")):
    # compare_digest takes the same time whether the key is almost right or totally wrong
    if not hmac.compare_digest(x_api_key.encode(), API_KEY.encode()):
        raise HTTPException(status_code=401, detail="Invalid API key")

    try:
        raw = base64.b64decode(body.raw_base64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="raw_base64 is not valid base64")

    try:
        result = score_email(raw)
    except MessageTooLarge:
        raise HTTPException(status_code=413, detail="Email is too large to analyze")
    except Exception:  # never leak internals (or email content) in an error message
        log.exception("analysis failed")
        raise HTTPException(status_code=500, detail="Analysis failed")

    log.info("analyzed email: verdict=%s score=%s signals=%s",
             result["verdict"], result["score"], [s["id"] for s in result["signals"]])
    return result
