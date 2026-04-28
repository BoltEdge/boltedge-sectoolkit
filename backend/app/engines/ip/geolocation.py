"""
SecToolkit 101 — IP Geolocation Engine

Tool: IP → IP Geolocation
Description: Locate IP addresses with detailed geographic information.
Input: IPv4 or IPv6 address
Output: Country, city, region, coordinates, timezone, ASN, ISP

Dependencies:
  - MaxMind GeoLite2-City.mmdb (app/data/)
  - MaxMind GeoLite2-ASN.mmdb (app/data/)
  - geoip2 library

Used by:
  - IP Geolocation tool (primary)
  - VPN Detection (for ASN/org context)
  - IP Reputation (enrichment)
"""
import geoip2.database
import geoip2.errors
from pathlib import Path
from app.config import Config
from app.utils.exceptions import (
    EngineError,
    DatabaseNotFoundError,
    InvalidInputError,
)
from app.utils.validators import validate_ip


class GeolocationEngine:
    """IP Geolocation lookup using MaxMind GeoLite2 databases."""

    def __init__(self, city_db: Path = None, asn_db: Path = None):
        self.city_db_path = city_db or Config.GEOIP_CITY_DB
        self.asn_db_path = asn_db or Config.GEOIP_ASN_DB
        self._city_reader = None
        self._asn_reader = None

    def _get_city_reader(self):
        """Lazy-load the GeoLite2 City database reader."""
        if self._city_reader is None:
            if not self.city_db_path.exists():
                raise DatabaseNotFoundError("GeoLite2-City.mmdb")
            try:
                self._city_reader = geoip2.database.Reader(str(self.city_db_path))
            except Exception as e:
                raise EngineError(f"Failed to open GeoLite2-City database: {str(e)}")
        return self._city_reader

    def _get_asn_reader(self):
        """Lazy-load the GeoLite2 ASN database reader."""
        if self._asn_reader is None:
            if not self.asn_db_path.exists():
                raise DatabaseNotFoundError("GeoLite2-ASN.mmdb")
            try:
                self._asn_reader = geoip2.database.Reader(str(self.asn_db_path))
            except Exception as e:
                raise EngineError(f"Failed to open GeoLite2-ASN database: {str(e)}")
        return self._asn_reader

    def lookup(self, ip_address: str) -> dict:
        """Perform full geolocation lookup for an IP address.

        Args:
            ip_address: IPv4 or IPv6 address string.

        Returns:
            Dict with geographic and network information.

        Raises:
            InvalidInputError: If IP is not valid.
            DatabaseNotFoundError: If GeoLite2 DB files are missing.
            EngineError: If lookup fails.
        """
        ip_address = validate_ip(ip_address)

        result = {
            "ip": ip_address,
            "location": self._lookup_city(ip_address),
            "network": self._lookup_asn(ip_address),
        }

        return result

    def _lookup_city(self, ip_address: str) -> dict:
        """Look up geographic location from the City database."""
        try:
            reader = self._get_city_reader()
            response = reader.city(ip_address)

            return {
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "region": response.subdivisions.most_specific.name if response.subdivisions else None,
                "region_code": response.subdivisions.most_specific.iso_code if response.subdivisions else None,
                "city": response.city.name,
                "postal_code": response.postal.code,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "accuracy_radius_km": response.location.accuracy_radius,
                "timezone": response.location.time_zone,
                "continent": response.continent.name,
                "continent_code": response.continent.code,
                "is_eu": response.country.is_in_european_union,
            }

        except geoip2.errors.AddressNotFoundError:
            return {
                "country": None,
                "country_code": None,
                "region": None,
                "region_code": None,
                "city": None,
                "postal_code": None,
                "latitude": None,
                "longitude": None,
                "accuracy_radius_km": None,
                "timezone": None,
                "continent": None,
                "continent_code": None,
                "is_eu": None,
            }
        except DatabaseNotFoundError:
            raise
        except Exception as e:
            raise EngineError(f"City lookup failed for {ip_address}: {str(e)}")

    def _lookup_asn(self, ip_address: str) -> dict:
        """Look up ASN and ISP from the ASN database."""
        try:
            reader = self._get_asn_reader()
            response = reader.asn(ip_address)

            return {
                "asn": f"AS{response.autonomous_system_number}" if response.autonomous_system_number else None,
                "asn_number": response.autonomous_system_number,
                "organisation": response.autonomous_system_organization,
                "network": str(response.network) if response.network else None,
            }

        except geoip2.errors.AddressNotFoundError:
            return {
                "asn": None,
                "asn_number": None,
                "organisation": None,
                "network": None,
            }
        except DatabaseNotFoundError:
            raise
        except Exception as e:
            raise EngineError(f"ASN lookup failed for {ip_address}: {str(e)}")

    def close(self):
        """Close database readers to free resources."""
        if self._city_reader:
            self._city_reader.close()
            self._city_reader = None
        if self._asn_reader:
            self._asn_reader.close()
            self._asn_reader = None