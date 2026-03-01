"""
BoltEdge SecToolkit — Application Configuration
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Base directory (sectoolkit-api/)
BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    """Base configuration — shared across all environments."""

    # --- Flask ---
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
    JSON_SORT_KEYS = False

    # --- Database ---
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- CORS ---
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3002").split(",")

    # --- Rate Limiting ---
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_DEFAULT = "60/minute"
    RATELIMIT_HEADERS_ENABLED = True

    # --- Rate Limits by Plan ---
    RATE_LIMIT_FREE = 30       # requests/min (web UI)
    RATE_LIMIT_PRO = 120       # requests/min (web UI)
    RATE_LIMIT_PRO_API = 60    # requests/min (API)
    RATE_LIMIT_ENTERPRISE = 0  # unlimited

    # --- Bulk Limits ---
    BULK_LIMIT_PRO = 50
    BULK_LIMIT_ENTERPRISE = 500

    # --- API Key ---
    API_KEY_PREFIX = "stk_"
    API_KEY_LENGTH = 40

    # --- Data Files ---
    DATA_DIR = BASE_DIR / "app" / "data"
    GEOIP_CITY_DB = DATA_DIR / "GeoLite2-City.mmdb"
    GEOIP_ASN_DB = DATA_DIR / "GeoLite2-ASN.mmdb"
    OUI_DATABASE = DATA_DIR / "oui-database.json"
    MITRE_DATA_DIR = DATA_DIR / "mitre"
    WAPPALYZER_DIR = DATA_DIR / "wappalyzer"

    # --- DNS ---
    DNS_TIMEOUT = 5
    DNS_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]

    # --- Network ---
    DEFAULT_TIMEOUT = 10
    PORT_SCAN_TIMEOUT = 3
    MAX_PORTS = 1000
    PING_COUNT = 4
    TRACEROUTE_MAX_HOPS = 30

    # --- SSL ---
    SSL_TIMEOUT = 10

    # --- HTTP ---
    HTTP_TIMEOUT = 15
    MAX_REDIRECTS = 10
    USER_AGENT = "BoltEdge-SecToolkit/1.0"

    # --- External API Keys (optional, loaded from env) ---
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
    GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")
    CENSYS_API_ID = os.getenv("CENSYS_API_ID", "")
    CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "")
    GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
    MAXMIND_LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY", "")

    # --- Feed Update Schedule ---
    FEED_HOURLY = ["tor_exit_nodes", "feodo_tracker"]
    FEED_DAILY = [
        "firehol", "ipsum", "urlhaus", "phishtank", "spamhaus_drop",
        "emerging_threats", "blocklist_de", "cins_army", "ssl_blacklist",
        "malwarebazaar", "vpn_ranges", "nvd_cve",
    ]
    FEED_WEEKLY = ["wappalyzer", "mitre_attack"]
    FEED_MONTHLY = ["maxmind_geolite2", "ieee_oui"]


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{BASE_DIR / 'dev.db'}"
    )


class TestingConfig(Config):
    """Testing configuration."""

    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    RATELIMIT_ENABLED = False


class ProductionConfig(Config):
    """Production configuration."""

    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "redis://localhost:6379/0")
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "https://sectoolkit.boltedge.co").split(",")

    def __init__(self):
        if not self.SECRET_KEY or self.SECRET_KEY == "change-me-in-production":
            raise ValueError("SECRET_KEY must be set in production")
        if not self.SQLALCHEMY_DATABASE_URI:
            raise ValueError("DATABASE_URL must be set in production")


# --- Config Selector ---
config_map = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config():
    """Return config class based on FLASK_ENV environment variable."""
    env = os.getenv("FLASK_ENV", "development")
    return config_map.get(env, DevelopmentConfig)