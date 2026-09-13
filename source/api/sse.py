"""Shared parsing for AgentCore Runtime SSE responses.

Used by handler.py (web /api/invoke) and gmail_poller.py (email chat): the
runtime streams progress text as SSE data lines and ends with one JSON object;
error events arrive as JSON *object* chunks rather than encoded strings.
"""

import json
import re


def _reassemble_sse(raw_text):
    """invoke_agent_runtime's response is Server-Sent Events: one `data: "<chunk>"`
    line per yielded chunk, each chunk a JSON-encoded string. Decode each line
    and concatenate to get back the plain text the entrypoint actually yielded.
    """
    parts = []
    for line in raw_text.split("\n"):
        line = line.strip()
        if not line.startswith("data:"):
            continue
        content = line[len("data:"):].strip()
        try:
            decoded = json.loads(content)
        except json.JSONDecodeError:
            parts.append(content)
        else:
            # Nova tool-use streams can yield JSON objects (not just encoded
            # strings) — re-serialise those so the join never mixes types.
            parts.append(decoded if isinstance(decoded, str) else json.dumps(decoded))
    return "".join(parts) if parts else raw_text


def _extract_trailing_json(raw_text):
    """The runtime streams phase-progress text, then ends with one JSON object.

    Scan from the end for a '{' whose decoded object's closing brace lands
    exactly at the end of the text — the outermost trailing object, not a
    nested one inside it. Same tail-JSON approach already used elsewhere in
    this project for CLI output.
    """
    trimmed = _reassemble_sse(raw_text).rstrip()
    decoder = json.JSONDecoder()
    for match in reversed(list(re.finditer(r"\{", trimmed))):
        start = match.start()
        try:
            obj, end = decoder.raw_decode(trimmed, start)
        except json.JSONDecodeError:
            continue
        if end == len(trimmed):
            return obj
    return None
