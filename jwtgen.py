# app.py
import os
import base64
import json
import asyncio
from typing import Tuple, Dict, Any

from flask import Flask, request, jsonify
from flask_cors import CORS

import httpx
from Crypto.Cipher import AES
from google.protobuf import json_format, message

# === Protobuf imports (ensure proto/ contains these generated files) ===
try:
    from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
except Exception as e:
    raise ImportError(
        "Protobuf modules not found. Place FreeFire_pb2.py, main_pb2.py, "
        "AccountPersonalShow_pb2.py inside the proto/ package. Original error: "
        f"{e}"
    )

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
RELEASEVERSION = "OB50"

# Flask app
app = Flask(__name__)
CORS(app)


# === Helper functions ===
def pad(b: bytes) -> bytes:
    pad_len = AES.block_size - (len(b) % AES.block_size)
    return b + bytes([pad_len]) * pad_len


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext))


async def json_to_proto_bytes(json_data: str, proto_message: message.Message) -> bytes:
    """Parse JSON string into provided proto message and return serialized bytes."""
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()


async def get_access_token(account_payload: str) -> Tuple[str, str]:
    """
    Calls the guest oauth token endpoint to exchange uid/password for an access token & open_id.
    Returns (access_token, open_id) or raises on HTTP error.
    """
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = f"{account_payload}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        "User-Agent": USERAGENT,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.post(url, data=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        access_token = data.get("access_token", "")
        open_id = data.get("open_id", "")
        return access_token, open_id


async def create_jwt_async(uid: str, password: str) -> Dict[str, Any]:
    """
    Core logic:
      - call get_access_token to obtain access_token & open_id
      - build LoginReq proto, serialize, AES encrypt, send to MajorLogin endpoint
      - parse LoginRes proto and return dict with uid, token, region, server_url
    On error returns {'error': '...','uid': uid}
    """
    try:
        account_str = f"uid={uid}&password={password}"
        token_val, open_id = await get_access_token(account_str)

        if not token_val or not open_id:
            return {"error": "Failed to obtain access token or open_id from guest endpoint.", "uid": uid}

        body = {
            "open_id": open_id,
            "open_id_type": "4",
            "login_token": token_val,
            "orign_platform_type": "4"
        }
        # Parse to proto and serialize
        proto_req = FreeFire_pb2.LoginReq()
        proto_bytes = await json_to_proto_bytes(json.dumps(body), proto_req)
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            "User-Agent": USERAGENT,
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "X-Unity-Version": "2022.3.47f1",
            "X-GA": "v1 1",
            "ReleaseVersion": RELEASEVERSION,
        }

        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(url, data=payload, headers=headers)
            resp.raise_for_status()
            # Parse response as LoginRes proto
            try:
                login_res = FreeFire_pb2.LoginRes.FromString(resp.content)
                login_res_json = json_format.MessageToDict(login_res)
            except Exception:
                # fallback: attempt to parse JSON body if server already returns JSON
                try:
                    login_res_json = resp.json()
                except Exception:
                    return {"error": "Failed to parse MajorLogin response.", "uid": uid}

        token = login_res_json.get("token") or login_res_json.get("Token") or ""
        region = login_res_json.get("lockRegion") or login_res_json.get("region") or ""
        server_url = login_res_json.get("serverUrl") or "https://loginbp.ggblueshark.com"

        if not token:
            return {"error": "MajorLogin returned no token.", "uid": uid, "raw": login_res_json}

        return {
            "uid": uid,
            "token": token,
            "region": region,
            "server_url": server_url
        }

    except httpx.HTTPStatusError as he:
        return {"error": f"HTTP error: {he.response.status_code} - {he.response.text}", "uid": uid}
    except Exception as e:
        return {"error": str(e), "uid": uid}


def create_jwt(uid: str, password: str) -> Dict[str, Any]:
    """Synchronous wrapper to run the async create_jwt_async."""
    return asyncio.run(create_jwt_async(uid, password))


# === Flask Routes ===

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "jwt-maker"}), 200


@app.route("/token", methods=["GET"])
def token_route():
    """
    Example:
      GET /token?uid=4211291069&password=BY_PARAHEX-...
    Success: returns a JSON list with single object:
      [ { "uid":"...", "token":"...", "region":"..." } ]
    Error: returns JSON object with "error" and HTTP 400.
    """
    uid = request.args.get("uid", "").strip()
    password = request.args.get("password", "").strip()

    if not uid or not password:
        return jsonify({"error": "Missing 'uid' or 'password' parameter."}), 400

    try:
        result = create_jwt(uid, password)
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

    if result.get("error"):
        # Return error in consistent structure (400)
        payload = {"error": result["error"], "uid": result.get("uid", uid)}
        # Optionally include raw response for debugging if present (but avoid leaking secrets in production)
        if "raw" in result:
            payload["raw"] = result["raw"]
        return jsonify(payload), 400

    # Success: return as list to match your example
    out = {
        "uid": result["uid"],
        "token": result["token"],
        "region": result.get("region", "")
    }
    return jsonify([out]), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)
