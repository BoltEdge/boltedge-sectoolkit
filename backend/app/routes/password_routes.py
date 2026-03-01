"""
BoltEdge SecToolkit â€” Password Tool Routes
"""
from flask import Blueprint
from app.utils.formatters import timed_tool, get_target, get_options

_engines = {}

def _get_engine(name):
    if name not in _engines:
        from app.engines.password.password_engines import (
            PasswordGeneratorEngine, PasswordStrengthEngine,
            PassphraseGeneratorEngine, BreachCheckEngine, EntropyCalculatorEngine)
        _map = {"generator": PasswordGeneratorEngine, "strength": PasswordStrengthEngine,
                "passphrase": PassphraseGeneratorEngine, "breach": BreachCheckEngine,
                "entropy": EntropyCalculatorEngine}
        if name in _map: _engines[name] = _map[name]()
    return _engines[name]

password_bp = Blueprint("password", __name__)

@password_bp.route("/generate", methods=["POST"])
@timed_tool("password.generate")
def password_generate():
    options = get_options()
    return _get_engine("generator").generate(length=options.get("length", 16),
        uppercase=options.get("uppercase", True), lowercase=options.get("lowercase", True),
        digits=options.get("digits", True), symbols=options.get("symbols", True),
        count=options.get("count", 1), exclude=options.get("exclude", "")), "password"

@password_bp.route("/strength", methods=["POST"])
@timed_tool("password.strength")
def password_strength():
    target = get_target(); return _get_engine("strength").analyse(target), target

@password_bp.route("/passphrase", methods=["POST"])
@timed_tool("password.passphrase")
def passphrase_generate():
    options = get_options()
    return _get_engine("passphrase").generate(words=options.get("words", 4),
        separator=options.get("separator", "-"), capitalize=options.get("capitalize", False),
        add_number=options.get("add_number", False)), "passphrase"

@password_bp.route("/breach", methods=["POST"])
@timed_tool("password.breach")
def breach_check():
    target = get_target(); return _get_engine("breach").check(target), target

@password_bp.route("/entropy", methods=["POST"])
@timed_tool("password.entropy")
def entropy_calc():
    target = get_target(); return _get_engine("entropy").calculate(target), target
