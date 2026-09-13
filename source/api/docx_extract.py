"""Full-fidelity, stdlib-only .docx extraction with an honest coverage report.

This is the S3-upload path's extractor (see handler.py's `upload_key` branch
of `_handle_invoke`): the whole file is fetched from S3 and read here — body
paragraphs AND tables, headers/footers, footnotes/endnotes, comments, core
properties, and every embedded image — instead of the ~24 KB of body text
the browser's client-side parser sends today. Brand contamination and the
architecture diagram both live outside the document body (headers/footers
and word/media/*), so a body-only extraction structurally cannot see them.

Deliberately independent of `handler.py`'s existing `_docx_to_text` (used by
the Google Drive fetch path, which only ever handles body+headers+footers of
a *trusted* Drive file and has no coverage-reporting requirement) — that
function keeps working unchanged for Drive. The table-to-text convention here
is intentionally identical to it (cells joined " | ", rows on their own
line), because the downstream cost-table regex in
source/agent/core/costs.py expects that exact shape regardless of which path
produced the text.

Only the standard library: zipfile + re (per part conversion) and
xml.etree.ElementTree isn't even needed — everything here is regex over the
already-well-formed OOXML that python-docx would otherwise need lxml for.
No new entry in requirements.txt.
"""

import base64
import re
import zipfile
from io import BytesIO

# ---------------------------------------------------------------------------
# Part classification — every zip entry lands in exactly one bucket.
# ---------------------------------------------------------------------------

_TEXT_PART_RULES = (
    (re.compile(r"^word/document\.xml$"), "body"),
    (re.compile(r"^word/header\d*\.xml$"), "header"),
    (re.compile(r"^word/footer\d*\.xml$"), "footer"),
    (re.compile(r"^word/footnotes\.xml$"), "footnotes"),
    (re.compile(r"^word/endnotes\.xml$"), "endnotes"),
    (re.compile(r"^word/comments\.xml$"), "comments"),
)
_CORE_PROPS_PART = "docProps/core.xml"
_MEDIA_PREFIX = "word/media/"

# Raster formats only — word/media/ can also hold .wmf/.emf vector metafiles,
# which are not "the largest raster image" this module is asked to find and
# which no downstream vision model here can decode anyway.
_RASTER_CONTENT_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".webp": "image/webp",
}
_VECTOR_CONTENT_TYPES = {
    ".wmf": "image/x-wmf",
    ".emf": "image/x-emf",
    ".svg": "image/svg+xml",
}


def _classify_part(name):
    """Return (classification, role). role is None for non-text parts."""
    for pattern, role in _TEXT_PART_RULES:
        if pattern.match(name):
            return "extracted", role
    if name == _CORE_PROPS_PART:
        return "extracted", "core_props"
    if name.startswith(_MEDIA_PREFIX):
        return "binary-asset", "image"
    return "skipped-not-content", None


# ---------------------------------------------------------------------------
# XML → text, matching handler.py's _docx_to_text join convention exactly:
# table cells join with " | ", rows end a line, paragraphs join with "\n".
# ---------------------------------------------------------------------------

def _unescape(text):
    return (
        text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        .replace("&quot;", '"').replace("&apos;", "'")
    )


def _convert_and_count(xml):
    """Convert one part's raw XML to readable text, and count paragraphs
    (body-level, i.e. outside any table) plus table rows/cells within it."""
    tables = re.findall(r"<w:tbl\b[\s\S]*?</w:tbl>", xml)
    table_rows = sum(len(re.findall(r"<w:tr\b", t)) for t in tables)
    table_cells = sum(len(re.findall(r"<w:tc\b", t)) for t in tables)
    body_only = re.sub(r"<w:tbl\b[\s\S]*?</w:tbl>", "", xml)
    paragraphs = len(re.findall(r"<w:p\b(?:\s|>)", body_only))

    def convert(fragment, p_sep):
        fragment = re.sub(r"<w:tab[^>]*/>", "\t", fragment)
        fragment = fragment.replace("</w:p>", p_sep)
        fragment = fragment.replace("</w:tc>", " | ").replace("</w:tr>", "\n")
        return fragment

    # Tables convert in place (cells " | ", rows "\n") before the rest of the
    # document converts paragraphs to "\n" — this preserves each table's
    # original position in reading order instead of hoisting it out.
    converted = re.sub(r"<w:tbl\b[\s\S]*?</w:tbl>", lambda m: convert(m.group(0), " "), xml)
    converted = convert(converted, "\n")
    converted = re.sub(r"<[^>]+>", "", converted)
    converted = _unescape(converted)
    lines = [
        re.sub(r"\s+\|", " |", re.sub(r"\|\s+", "| ", line)).rstrip(" |").strip()
        for line in converted.splitlines()
        if line.strip()
    ]
    text = "\n".join(lines)
    return text, {"paragraphs": paragraphs, "table_rows": table_rows, "table_cells": table_cells}


def _count_notes(xml, tag):
    """Count <w:footnote>/<w:endnote>/<w:comment> elements, excluding the
    synthetic separator/continuationSeparator footnote/endnote entries that
    Word always emits (id -1/0) and that carry no author content."""
    entries = re.findall(rf"<w:{tag}\b[^>]*>", xml)
    return sum(1 for e in entries if "separator" not in e)


def _parse_core_props(xml):
    def grab(tag):
        m = re.search(rf"<{tag}[^>]*>([\s\S]*?)</{tag}>", xml)
        return _unescape(m.group(1)).strip() if m else ""

    return {
        "title": grab("dc:title"),
        "creator": grab("dc:creator"),
        "last_modified_by": grab("cp:lastModifiedBy"),
        "created": grab("dcterms:created"),
        "modified": grab("dcterms:modified"),
    }


# Words that appear beside an architecture diagram in a SOW. Used to pick the
# right image rather than the biggest one.
_DIAGRAM_CUES = (
    "architecture", "solution architecture", "target state", "topology",
    "data flow", "reference architecture", "diagram", "figure",
)


def _diagram_candidates(zf, doc_xml):
    """Media parts referenced near architecture wording, best first.

    "Largest raster" is the wrong heuristic: a SOW's biggest image is usually a
    full-bleed cover graphic. On a real document that picked a 1.2 MB decorative
    gradient over the 322 KB architecture diagram, and the review then ran
    against the gradient while reporting success.

    Word references an image as r:embed="rIdN"; document.xml.rels maps that to
    word/media/*. We locate each reference in the raw XML, strip tags from a
    window around it, and score by how close an architecture cue sits.
    """
    import re as _re
    try:
        rels = zf.read("word/_rels/document.xml.rels").decode("utf-8", "ignore")
    except KeyError:
        return []
    target = {}
    for m in _re.finditer(r'Id="([^"]+)"[^>]*Target="([^"]+)"', rels):
        tgt = m.group(2).replace("../", "")
        if tgt.startswith("media/"):
            target[m.group(1)] = "word/" + tgt

    scored = {}
    for m in _re.finditer(r'r:embed="([^"]+)"', doc_xml):
        part = target.get(m.group(1))
        if not part:
            continue
        lo = max(0, m.start() - 4000)
        window = _re.sub(r"<[^>]+>", " ", doc_xml[lo:m.start() + 1500]).lower()
        best = 0
        for cue in _DIAGRAM_CUES:
            if cue in window:
                # Longer, more specific cues outrank a bare "figure".
                best = max(best, len(cue))
        if best:
            scored[part] = max(scored.get(part, 0), best)
    return sorted(scored.items(), key=lambda kv: -kv[1])


def extract_docx(data: bytes, use_vision: bool = False) -> dict:
    """Extract everything a .docx zip holds, with a coverage report of
    exactly what was and was not read. Never raises on a malformed *part* —
    that part is recorded in coverage.unread_parts instead. Only raises if
    `data` is not a zip at all (caller should treat that as "not a valid
    .docx" and answer 400)."""
    with zipfile.ZipFile(BytesIO(data)) as zf:
        names = zf.namelist()

        text_sections = []          # ordered [(role, text), ...] for the combined "text" output
        header_count = 0
        footer_count = 0
        footnote_count = 0
        endnote_count = 0
        comment_count = 0
        paragraphs_total = 0
        table_rows_total = 0
        table_cells_total = 0

        images = []                 # [{"part", "bytes", "content_type"}]
        # Raw body XML, kept for locating image references by proximity to
        # architecture wording (see _diagram_candidates).
        try:
            document_xml = zf.read("word/document.xml").decode("utf-8", "ignore")
        except KeyError:
            document_xml = ""
        core_props = {}

        parts_report = []           # [{"name", "classification", "chars"}]
        chars_by_part = {}
        unread_parts = []           # [{"part", "reason"}]

        content_parts_total = 0
        content_parts_extracted = 0

        for name in names:
            classification, role = _classify_part(name)
            chars = None

            if classification == "extracted":
                content_parts_total += 1
                try:
                    raw = zf.read(name)
                except KeyError as exc:  # pragma: no cover — zipfile guarantees membership from namelist()
                    unread_parts.append({"part": name, "reason": f"could not read zip entry: {exc}"})
                    parts_report.append({"name": name, "classification": classification, "chars": None})
                    continue
                try:
                    xml = raw.decode("utf-8", errors="strict")
                    if role == "core_props":
                        core_props = _parse_core_props(xml)
                        text = " ".join(v for v in core_props.values() if v)
                        chars = len(text)
                    elif role in ("footnotes", "endnotes", "comments"):
                        tag = {"footnotes": "footnote", "endnotes": "endnote", "comments": "comment"}[role]
                        count = _count_notes(xml, tag)
                        if role == "footnotes":
                            footnote_count += count
                        elif role == "endnotes":
                            endnote_count += count
                        text, counts = _convert_and_count(xml)
                        paragraphs_total += counts["paragraphs"]
                        table_rows_total += counts["table_rows"]
                        table_cells_total += counts["table_cells"]
                        if role == "comments":
                            comment_count += count
                        chars = len(text)
                    else:  # body, header, footer
                        text, counts = _convert_and_count(xml)
                        paragraphs_total += counts["paragraphs"]
                        table_rows_total += counts["table_rows"]
                        table_cells_total += counts["table_cells"]
                        if role == "header":
                            header_count += 1
                        elif role == "footer":
                            footer_count += 1
                        chars = len(text)
                    text_sections.append((role, text))
                    content_parts_extracted += 1
                except Exception as exc:  # noqa: BLE001 — one bad part must not sink the whole extraction
                    unread_parts.append({"part": name, "reason": f"parse error: {exc}"})
                parts_report.append({"name": name, "classification": "extracted", "chars": chars})

            elif classification == "binary-asset":
                content_parts_total += 1
                try:
                    raw = zf.read(name)
                    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
                    content_type = (
                        _RASTER_CONTENT_TYPES.get(ext)
                        or _VECTOR_CONTENT_TYPES.get(ext)
                        or "application/octet-stream"
                    )
                    images.append({
                        "part": name,
                        "bytes": len(raw),
                        "content_type": content_type,
                        "_raster": ext in _RASTER_CONTENT_TYPES,
                        "_ext": ext,
                        "_data": raw,
                    })
                    content_parts_extracted += 1
                    chars = None
                except Exception as exc:  # noqa: BLE001
                    unread_parts.append({"part": name, "reason": f"could not read image: {exc}"})
                parts_report.append({"name": name, "classification": "binary-asset", "chars": None})

            else:
                parts_report.append({"name": name, "classification": "skipped-not-content", "chars": None})

        # Largest RASTER image is the likely architecture diagram. Vector
        # metafiles (.wmf/.emf) and any image this module could not decode
        # the bytes of are never picked — we don't try to interpret the
        # image, only to hand the best candidate onward as bytes.
        raster_images = [i for i in images if i["_raster"]]
        diagram_base64 = diagram_format = diagram_part = None
        diagram_reason = None
        diagram_services = []
        if raster_images:
            by_part = {i["part"]: i for i in raster_images}
            largest = None
            for part, _score in _diagram_candidates(zf, document_xml or ""):
                if part in by_part:
                    largest = by_part[part]
                    diagram_reason = "referenced near architecture wording"
                    break
            if largest is None and use_vision:
                # No architecture wording nearby. Look INSIDE the candidates for
                # AWS service icons — the signal that actually distinguishes a
                # diagram from full-bleed cover art, which "largest raster"
                # reliably gets wrong.
                try:
                    icon_scores = score_images_by_aws_icons(raster_images)
                except Exception:                      # never fail extraction on this
                    icon_scores = {}
                diagram_like = {pt: v for pt, v in icon_scores.items()
                                if v.get("is_diagram") and v.get("icons", 0) > 0}
                if diagram_like:
                    best_part = max(diagram_like, key=lambda pt: diagram_like[pt]["icons"])
                    if best_part in by_part:
                        largest = by_part[best_part]
                        n = diagram_like[best_part]["icons"]
                        diagram_services = diagram_like[best_part].get("services") or []
                        diagram_reason = f"AWS service icons detected in image ({n} icons)"
            if largest is None and not use_vision:
                # Deterministic-only mode: no way to tell a diagram from cover
                # art, so keep the historical largest-raster guess and label it.
                largest = max(raster_images, key=lambda i: i["bytes"])
                diagram_reason = "largest raster (no architecture cue; vision not enabled)"
            elif largest is None:
                # Vision ran and found no AWS service icons in any candidate.
                # Many SOWs genuinely contain no architecture diagram — only a
                # cover graphic and logos. Returning that graphic anyway sends
                # a gradient to the diagram phase and invites a hallucinated
                # reading, so return NO diagram instead.
                diagram_reason = "no architecture diagram found (vision found no AWS icons)"
            if largest is not None:
                diagram_base64 = base64.b64encode(largest["_data"]).decode("ascii")
                diagram_format = largest["_ext"].lstrip(".")
                if diagram_format == "jpg":
                    diagram_format = "jpeg"
                diagram_part = largest["part"]

        # Public image list never carries the raw bytes — only the largest
        # (the diagram candidate) is returned as base64, per the "list every
        # image, return only the likely diagram" contract.
        public_images = [
            {"part": i["part"], "bytes": i["bytes"], "content_type": i["content_type"]}
            for i in images
        ]

        combined_text = "\n\n".join(text for _role, text in text_sections if text)
        total_chars = sum(len(text) for _role, text in text_sections)

        for p in parts_report:
            if p["chars"] is not None:
                chars_by_part[p["name"]] = p["chars"]

        coverage_pct = (
            round(100.0 * content_parts_extracted / content_parts_total, 1)
            if content_parts_total
            else 100.0
        )

        coverage = {
            "parts": parts_report,
            "counts": {
                "paragraphs": paragraphs_total,
                "table_rows": table_rows_total,
                "table_cells": table_cells_total,
                "headers": header_count,
                "footers": footer_count,
                "footnotes": footnote_count,
                "endnotes": endnote_count,
                "comments": comment_count,
                "images": len(images),
            },
            "chars_by_part": chars_by_part,
            "total_chars": total_chars,
            "unread_parts": unread_parts,
            "content_parts_total": content_parts_total,
            "content_parts_extracted": content_parts_extracted,
            "coverage_pct": coverage_pct,
        }

        return {
            "text": combined_text,
            "core_props": core_props,
            "images": public_images,
            "diagram_base64": diagram_base64,
            "diagram_selected_by": diagram_reason,
            "diagram_services": diagram_services,
            "diagram_format": diagram_format,
            "diagram_part": diagram_part,
            "coverage": coverage,
        }

# Images worth asking a model about: below this, a raster is an icon or a logo,
# not an architecture diagram.
_VISION_MIN_BYTES = 20_000
_VISION_MAX_CANDIDATES = 4

_ICON_PROMPT = (
    "Look at this image. Answer ONLY with bare JSON, no prose:\n"
    '{"is_architecture_diagram": true|false, "aws_services": ["Amazon S3", ...], '
    '"icon_count": <number of distinct AWS service icons you can see>}\n'
    "An AWS architecture diagram shows named AWS service icons connected by arrows "
    "or grouped inside VPC/Region boundaries. A cover page, logo, screenshot, photo "
    "or decorative graphic is NOT an architecture diagram."
)


def score_images_by_aws_icons(images, model_id=None, region=None):
    """Ask a vision model which candidate image actually shows AWS service icons.

    Proximity to the word "architecture" is a good signal but not a sufficient
    one: a document may reference no such heading, and the largest-raster
    fallback reliably picks full-bleed cover art. Looking INSIDE the image for
    AWS service icons is the signal that actually distinguishes a diagram.

    Returns {part: {"icons": int, "services": [...], "is_diagram": bool}}.
    Never raises: if Bedrock is unavailable the caller keeps its deterministic
    choice rather than failing the whole extraction.
    """
    import base64 as _b64
    import json as _json
    import os as _os

    candidates = sorted(
        [i for i in images if i.get("_raster") and i.get("bytes", 0) >= _VISION_MIN_BYTES],
        key=lambda i: -i["bytes"],
    )[:_VISION_MAX_CANDIDATES]
    if not candidates:
        return {}

    model = model_id or _os.environ.get("FAST_MODEL_ID") or "amazon.nova-lite-v1:0"
    try:
        import boto3
        client = boto3.client("bedrock-runtime", region_name=region or _os.environ.get("AWS_REGION", "us-east-1"))
    except Exception:
        return {}

    scored = {}
    for img in candidates:
        fmt = (img.get("_ext") or "").lstrip(".").lower()
        if fmt == "jpg":
            fmt = "jpeg"
        if fmt not in {"png", "jpeg", "gif", "webp"}:
            continue
        try:
            resp = client.converse(
                modelId=model,
                messages=[{"role": "user", "content": [
                    {"image": {"format": fmt, "source": {"bytes": img["_data"]}}},
                    {"text": _ICON_PROMPT},
                ]}],
                inferenceConfig={"maxTokens": 400, "temperature": 0},
            )
            text = resp["output"]["message"]["content"][0]["text"]
            start, end = text.find("{"), text.rfind("}")
            data = _json.loads(text[start:end + 1]) if start >= 0 else {}
        except Exception:
            continue
        services = [s for s in (data.get("aws_services") or []) if isinstance(s, str)]
        scored[img["part"]] = {
            "icons": int(data.get("icon_count") or len(services)),
            "services": services,
            "is_diagram": bool(data.get("is_architecture_diagram")),
        }
    return scored
