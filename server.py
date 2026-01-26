
import os
import time
import base64
import urllib.parse
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

import requests
from flask import Flask, request, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

EBAY_ENV = os.getenv("EBAY_ENV", "production").lower()
EBAY_CLIENT_ID = os.getenv("EBAY_CLIENT_ID", "")
EBAY_CLIENT_SECRET = os.getenv("EBAY_CLIENT_SECRET", "")

if not EBAY_CLIENT_ID or not EBAY_CLIENT_SECRET:
    raise RuntimeError("Missing EBAY_CLIENT_ID / EBAY_CLIENT_SECRET")

EBAY_API_ROOT = "https://api.ebay.com" if EBAY_ENV == "production" else "https://api.sandbox.ebay.com"
OAUTH_TOKEN_URL = f"{EBAY_API_ROOT}/identity/v1/oauth2/token"
BROWSE_SEARCH_URL = f"{EBAY_API_ROOT}/buy/browse/v1/item_summary/search"
DEFAULT_CATEGORY_ID = "6000"  # Auto Parts & Accessories

BROWSE_SCOPE = "https://api.ebay.com/oauth/api_scope"

@dataclass
class TokenCache:
    access_token: str = ""
    expires_at: float = 0.0  

TOKEN_CACHE = TokenCache()

def _basic_auth_header(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    b64 = base64.b64encode(raw).decode("ascii")
    return f"Basic {b64}"

def get_app_token() -> str:
    now = time.time()
    if TOKEN_CACHE.access_token and now < (TOKEN_CACHE.expires_at - 30):
        return TOKEN_CACHE.access_token

    headers = {
        "Authorization": _basic_auth_header(EBAY_CLIENT_ID, EBAY_CLIENT_SECRET),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "client_credentials",
        "scope": BROWSE_SCOPE,
    }

    r = requests.post(OAUTH_TOKEN_URL, headers=headers, data=data, timeout=20)
    if r.status_code != 200:
        raise RuntimeError(f"OAuth token error {r.status_code}: {r.text}")

    payload = r.json()
    TOKEN_CACHE.access_token = payload["access_token"]
    TOKEN_CACHE.expires_at = now + int(payload.get("expires_in", 0))
    return TOKEN_CACHE.access_token

def build_compatibility_filter(
    make: Optional[str],
    model: Optional[str],
    year: Optional[str],
    trim: Optional[str],
    engine: Optional[str],
) -> Optional[str]:
    parts = []
    if year:   parts.append(f"Year:{year}")
    if make:   parts.append(f"Make:{make}")
    if model:  parts.append(f"Model:{model}")
    if trim:   parts.append(f"Trim:{trim}")
    if engine: parts.append(f"Engine:{engine}")
    if not parts:
        return None
    return ";".join(parts)

def normalize_items(search_json: Dict[str, Any]) -> Dict[str, Any]:
    items = []
    for it in search_json.get("itemSummaries", []) or []:
        price = it.get("price", {}) or {}
        image = it.get("image", {}) or {}
        items.append({
            "itemId": it.get("itemId"),
            "title": it.get("title"),
            "condition": it.get("condition"),
            "price": {
                "value": price.get("value"),
                "currency": price.get("currency"),
            },
            "imageUrl": image.get("imageUrl"),
            "itemWebUrl": it.get("itemWebUrl"),
            "compatibilityMatch": it.get("compatibilityMatch"),
            "compatibilityProperties": it.get("compatibilityProperties"),
        })

    return {
        "href": search_json.get("href"),
        "total": search_json.get("total"),
        "limit": search_json.get("limit"),
        "offset": search_json.get("offset"),
        "items": items,
    }

@app.get("/health")
def health():
    return jsonify({"ok": True, "env": EBAY_ENV})

from requests import RequestException

@app.get("/api/ebay/search")
def ebay_search():
    try:
        vehicle_make = request.args.get("brand")
        vehicle_model = request.args.get("model")
        query = request.args.get("q")
        limit = request.args.get("limit", "20")
        offset = request.args.get("offset", "0")

        year = request.args.get("year")
        trim = request.args.get("trim")
        engine = request.args.get("engine")

        marketplace_id = request.args.get("marketplace_id", "EBAY_US")
        delivery_country = request.args.get("delivery_country", "US")

        if not query:
            return jsonify({"error": "Missing q"}), 400
        if vehicle_make:
            query = f"{vehicle_make} {query}"
        if vehicle_model:
            query = f"{vehicle_model} {query}"
        if trim:
            query = f"{trim} {query}"
        if year:
            query = f"{year} {query}"
        if engine:
            query = f"{engine} {query}"

        token = get_app_token()

        headers = {
            "Authorization": f"Bearer {token}",
            "X-EBAY-C-MARKETPLACE-ID": marketplace_id,
            "Accept": "application/json",
        }

        params = {
            "q": query,
            "category_ids": DEFAULT_CATEGORY_ID,
            "limit": limit,
            "offset": offset,
        }

        compatibility_filter = build_compatibility_filter(
            make=vehicle_make, model=vehicle_model, year=year, trim=trim, engine=engine
        )
        if compatibility_filter:
            params["compatibility_filter"] = compatibility_filter

        if delivery_country:
            params["filter"] = f"deliveryCountry:{delivery_country}"

        r = requests.get(BROWSE_SEARCH_URL, headers=headers, params=params, timeout=20)

        if r.status_code != 200:
            return jsonify({
                "error": "eBay search failed",
                "status": r.status_code,
                "details": r.text
            }), 502

        return jsonify(normalize_items(r.json()))

    except RequestException as e:
        return jsonify({"error": "Network error", "details": str(e)}), 502
    except Exception as e:
        # Mostra l’errore reale invece del 500 HTML
        return jsonify({"error": "Internal error", "details": str(e)}), 500
