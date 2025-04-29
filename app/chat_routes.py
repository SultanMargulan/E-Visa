from flask import Blueprint, request, Response, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv
import os, json, openai
from itertools import chain
from app import limiter

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

bp = Blueprint("chat", __name__)
CORS(bp)

@bp.route("/", methods=["GET"])
def chat_page():
    """Serve the Visa-Bot chat UI (templates/chat.html)."""
    return render_template("chat.html")

@bp.route("/api/chat", methods=["POST", "OPTIONS"])
@limiter.limit("5/second")
def chat_stream():
    if request.method == "OPTIONS":
        return Response("", status=200)
        
    messages = request.json.get("messages", [])
    SYSTEM = {
        "role": "system",
        "content": (
            "You are VisaBot, a concise expert on international travel paperwork. "
            "⚠️ You must refuse or briefly deflect any question that is NOT about visas, "
            "immigration rules, passports, consular processes, or travel logistics."
        )
    }
    # guarantee system msg is first — duplicates won’t hurt
    msg_chain = [SYSTEM] + [m for m in messages if m["role"] != "system"]

    def stream():
        resp = openai.chat.completions.create(
            model="gpt-4o-mini-2024-07-18",
            messages=msg_chain,
            stream=True,
            temperature=0.3,
            max_tokens=1024,
        )
        for chunk in resp:
            yield f"data:{chunk.choices[0].delta.content or ''}\n\n"
    return Response(stream(), mimetype="text/event-stream")
