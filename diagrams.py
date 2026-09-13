"""
Regenerate the AWS SOW Validator architecture diagram PNG.

Requirements:
    brew install graphviz
    pip install diagrams

Usage:
    python3 diagrams.py
"""

import os
import shutil
import sys

_here = os.path.dirname(os.path.abspath(__file__))
if _here in sys.path:
    sys.path.remove(_here)

from diagrams import Cluster, Diagram, Edge
from diagrams.aws.compute import Lambda
from diagrams.aws.database import Dynamodb
from diagrams.aws.ml import Bedrock
from diagrams.aws.network import CloudFront
from diagrams.aws.security import WAF, Cognito
from diagrams.aws.storage import S3
from diagrams.custom import Custom
from diagrams.onprem.client import User


def _inline_svg_images(svg_path):
    """Embed referenced PNGs as data URIs.

    Graphviz writes icon references as absolute paths to wherever the `diagrams`
    package happens to live on the machine that generated the file. That makes
    the SVG useless anywhere else — icons silently vanish when it is served from
    S3 or rendered on GitHub. Inlining makes the file self-contained.
    """
    import base64
    import re as _re
    from urllib.parse import unquote

    with open(svg_path, "r", encoding="utf-8") as fh:
        svg = fh.read()

    missing = []

    def repl(match):
        attr, path = match.group(1), unquote(match.group(2))
        if path.startswith("data:") or path.startswith("#"):
            return match.group(0)
        if not os.path.isfile(path):
            missing.append(path)
            return match.group(0)
        with open(path, "rb") as fh:
            payload = base64.b64encode(fh.read()).decode("ascii")
        ext = os.path.splitext(path)[1].lower()
        mime = "image/svg+xml" if ext == ".svg" else "image/png"
        return f'{attr}="data:{mime};base64,{payload}"'

    svg = _re.sub(r'(xlink:href|href)="([^"#][^"]*)"', repl, svg)

    with open(svg_path, "w", encoding="utf-8") as fh:
        fh.write(svg)

    if missing:
        raise SystemExit(f"icons not found, diagram would render blank: {missing}")
    return svg.count("data:image")

GRAPH = {
    "bgcolor": "white",
    "pad": "0.5",
    "fontsize": "13",
    "fontname": "Helvetica",
    "splines": "spline",
}
NODE = {"fontsize": "11", "fontname": "Helvetica"}
EDGE = {"fontsize": "9", "fontname": "Helvetica"}

_ASSETS = os.path.join(_here, "assets")
_ICONS = os.path.join(_ASSETS, "icons")
ICON_RUNTIME = os.path.join(_ICONS, "agentcore-runtime.png")
# Same-origin copies the deployed site serves relatively — see the note by
# the copy step at the bottom of this file for why these are duplicated
# rather than referenced from assets/ directly.
_SITE_DIR = os.path.join(_here, "source", "web")

_C_EDGE = dict(bgcolor="#EBF5FB", style="rounded", pencolor="#90CAF9", penwidth="2")
_C_WEB = dict(bgcolor="#FFF3E0", style="rounded", pencolor="#FFB74D", penwidth="2", margin="24")
_C_AGENTCORE = dict(bgcolor="#F0FFF4", style="rounded", pencolor="#81C995", penwidth="3", margin="28")
_C_GATEWAY_TARGET = dict(bgcolor="#F0FFF4", style="rounded", pencolor="#81C995", penwidth="2")
_C_SECURITY = dict(bgcolor="#FFF0F0", style="rounded", pencolor="#EF9A9A", penwidth="2")

os.makedirs(_ASSETS, exist_ok=True)

with Diagram(
    "AWS SOW Validator | AWS Architecture | v2.0",
    filename=os.path.join(_ASSETS, "architecture"),
    show=False,
    outformat=["png", "svg"],
    direction="TB",
    graph_attr={**GRAPH, "nodesep": "0.5", "ranksep": "0.9", "size": "18,22"},
    node_attr=NODE,
    edge_attr=EDGE,
):
    user = User("AWS Partner /\npre-sales reviewer")

    # ---- Edge: public entry, protected by WAF -----------------------------
    with Cluster("Edge (public)", graph_attr=_C_EDGE):
        waf = WAF("AWS WAF\nmanaged rules +\nrate limit\n(us-east-1, CLOUDFRONT scope)")
        cdn = CloudFront("CloudFront\nsingle domain,\nrouted behaviors")
        waf >> Edge(label="inspect") >> cdn

    # ---- Identity: self-service signup, allowlisted ------------------------
    with Cluster("Identity", graph_attr=_C_SECURITY):
        userpool = Cognito("Cognito user pool\nself sign-up +\nemail verification")
        presignup = Lambda("PreSignUp trigger\nemail allowlist\n(enforced server-side)")
        userpool >> Edge(style="dashed", label="every\nsign-up") >> presignup

    # ---- Web layer: Tier 1 runs here, no model call -----------------------
    with Cluster("Web layer", graph_attr=_C_WEB):
        site = S3("S3 static site\nvalidator + sample report\n(OAC, no public bucket)")
        web_fn = Lambda("web-invoke Lambda\nTier 1 deterministic engine\n+ JWT verify + 2 MB cap")
        users = Dynamodb("users table\nfree-run quota\n(atomic UpdateItem)")
        views = Dynamodb("share-views table\n3 views / 30 days")
        web_fn >> Edge(label="consume\nfree run") >> users
        web_fn >> Edge(label="atomic\nUpdateItem") >> views

    # ---- Tier 2: the model path ------------------------------------------
    with Cluster("Amazon Bedrock AgentCore  (Tier 2 — optional)", graph_attr=_C_AGENTCORE):
        runtime = Custom("AgentCore Runtime\n5-phase agent", ICON_RUNTIME)
        nova = Bedrock("Amazon Bedrock\nAmazon Nova\n(reads; never decides numbers)")
        memory = Custom("Memory\nSEMANTIC + SUMMARIZATION\n+ USER_PREFERENCE", ICON_RUNTIME)
        gateway = Custom("Gateway\nMCP, semantic search", ICON_RUNTIME)
        code_interp = Custom("Code Interpreter\nwhat-if pricing", ICON_RUNTIME)
        knowledge_base = Custom("Knowledge Base\nFAQ vector search", ICON_RUNTIME)

        with Cluster("Policy Engine (Cedar)", graph_attr=_C_SECURITY):
            policy_note = Custom("read-only tools\nenforced, not prompted", ICON_RUNTIME)

        runtime >> Edge(label="invoke\nmodel") >> nova
        runtime >> Edge(label="session recall\n(short + long term)") >> memory
        runtime >> Edge(label="MCP\ntools/call") >> gateway
        runtime >> Edge(style="dashed", label="sandbox exec") >> code_interp
        runtime >> Edge(style="dashed", label="Retrieve") >> knowledge_base
        gateway >> Edge(style="dashed", label="every call\nchecked") >> policy_note

    with Cluster("Gateway target", graph_attr=_C_GATEWAY_TARGET):
        docs_fn = Lambda("aws-documentation\nMCP Lambda")

    with Cluster("Knowledge base source", graph_attr=_C_GATEWAY_TARGET):
        faq_bucket = S3("S3\ncurated FAQ")

    user >> Edge(label="HTTPS") >> waf
    user >> Edge(style="dashed", label="sign up /\nsign in") >> userpool
    cdn >> Edge(label="static") >> site
    cdn >> Edge(label="/api/* (OAC-signed,\nBearer ID token)") >> web_fn
    web_fn >> Edge(style="dashed", label="verify JWT\n(JWKS)") >> userpool
    web_fn >> Edge(label="InvokeAgentRuntime\n(IAM, scoped to one ARN)") >> runtime
    gateway >> Edge(label="Lambda\ninvoke") >> docs_fn
    knowledge_base >> Edge(style="dashed", label="ingested from") >> faq_bucket
    web_fn >> Edge(style="dashed", label="share link") >> site

# Cost: Tier 1 ~$0.0003/review (no model call) - Tier 2 $0.02-0.08/review
# (AgentCore Runtime + Amazon Nova) - WAF ~$6/month - everything else scale-to-zero


_svg = os.path.join(_ASSETS, "architecture.svg")
_png = os.path.join(_ASSETS, "architecture.png")
if os.path.exists(_svg):
    _n = _inline_svg_images(_svg)
    print(f"architecture.svg: inlined {_n} icons as data URIs")

# The deployed site serves architecture.svg/.png as same-origin assets,
# referenced relatively from source/web/index.html — they must physically
# live alongside index.html, not just under assets/, so every regeneration
# copies both files there too.
if os.path.exists(_SITE_DIR):
    if os.path.exists(_svg):
        shutil.copy2(_svg, os.path.join(_SITE_DIR, "architecture.svg"))
    if os.path.exists(_png):
        shutil.copy2(_png, os.path.join(_SITE_DIR, "architecture.png"))
