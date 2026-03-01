"""
BoltEdge SecToolkit â€” URL Tool Routes
"""
from flask import Blueprint
from app.utils.formatters import timed_tool, get_target, get_options

_engines = {}

def _get_engine(name):
    if name not in _engines:
        if name == "scanner":
            from app.engines.url.url_scanner import URLScannerEngine; _engines[name] = URLScannerEngine()
        elif name == "decoder":
            from app.engines.url.url_decoder import URLDecoderEngine; _engines[name] = URLDecoderEngine()
        elif name == "parser":
            from app.engines.url.url_parser import URLParserEngine; _engines[name] = URLParserEngine()
        elif name == "redirect":
            from app.engines.url.redirect_checker import RedirectCheckerEngine; _engines[name] = RedirectCheckerEngine()
        elif name == "links":
            from app.engines.url.link_extractor import LinkExtractorEngine; _engines[name] = LinkExtractorEngine()
        elif name == "headers":
            from app.engines.url.http_headers import HTTPHeadersEngine; _engines[name] = HTTPHeadersEngine()
        elif name == "reputation":
            from app.engines.url.url_reputation import URLReputationEngine; _engines[name] = URLReputationEngine()
        elif name == "screenshot":
            from app.engines.url.screenshot_capture import ScreenshotCaptureEngine; _engines[name] = ScreenshotCaptureEngine()
        elif name == "techstack":
            from app.engines.url.tech_stack_detector import TechStackDetectorEngine; _engines[name] = TechStackDetectorEngine()
        elif name == "opengraph":
            from app.engines.url.open_graph_parser import OpenGraphParserEngine; _engines[name] = OpenGraphParserEngine()
    return _engines[name]

url_bp = Blueprint("url", __name__)

@url_bp.route("/scan", methods=["POST"])
@timed_tool("url.scanner")
def url_scanner():
    target = get_target(); return _get_engine("scanner").scan(target), target

@url_bp.route("/decode", methods=["POST"])
@timed_tool("url.decoder")
def url_decoder():
    target = get_target(); return _get_engine("decoder").decode(target), target

@url_bp.route("/parse", methods=["POST"])
@timed_tool("url.parser")
def url_parser():
    target = get_target(); return _get_engine("parser").parse(target), target

@url_bp.route("/redirects", methods=["POST"])
@timed_tool("url.redirect_checker")
def redirect_checker():
    target = get_target(); options = get_options()
    return _get_engine("redirect").check(target, max_redirects=options.get("max_redirects", 20)), target

@url_bp.route("/links", methods=["POST"])
@timed_tool("url.link_extractor")
def link_extractor():
    target = get_target(); return _get_engine("links").extract(target), target

@url_bp.route("/headers", methods=["POST"])
@timed_tool("url.http_headers")
def http_headers():
    target = get_target(); return _get_engine("headers").inspect(target), target

@url_bp.route("/reputation", methods=["POST"])
@timed_tool("url.reputation")
def url_reputation():
    target = get_target(); return _get_engine("reputation").lookup(target), target

@url_bp.route("/screenshot", methods=["POST"])
@timed_tool("url.screenshot")
def screenshot_capture():
    target = get_target(); return _get_engine("screenshot").capture(target), target

@url_bp.route("/techstack", methods=["POST"])
@timed_tool("url.techstack")
def tech_stack():
    target = get_target(); return _get_engine("techstack").detect(target), target

@url_bp.route("/opengraph", methods=["POST"])
@timed_tool("url.opengraph")
def open_graph():
    target = get_target(); return _get_engine("opengraph").parse(target), target
