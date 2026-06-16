"""
XDR Platform — Enrichment Pipeline
=====================================
Enriches every alert with three data sources:

  1. GeoIP       — Country, city, ISP, coordinates (via MaxMind GeoLite2)
  2. Threat Intel — AbuseIPDB, VirusTotal, simulated OTX/MISP lookups
  3. Host Context — Criticality rating from the host inventory config

All external calls are async, time-bounded, and fail-safe:
a network timeout or API error degrades gracefully rather than blocking
the alert pipeline.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
from datetime import datetime
from typing import Any, Dict, Optional

import httpx

from backend.core.settings import settings
from backend.core.logging_config import get_logger

log = get_logger("pipeline.enrichment")

# ── Constants ─────────────────────────────────────────────────────────────────

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

_EMPTY_GEO = {"country": "Unknown", "country_code": "N/A", "city": "Unknown",
              "latitude": 0.0, "longitude": 0.0, "isp": "Unknown", "asn": ""}

_EMPTY_INTEL = {"abuse_score": 0, "abuse_reports": 0, "vt_malicious": 0,
                "vt_suspicious": 0, "otx_pulses": 0, "is_known_bad": False,
                "threat_sources": []}


# ── Utility ───────────────────────────────────────────────────────────────────

def _is_private_ip(ip: str) -> bool:
    """Return True if *ip* is RFC-1918 / loopback — skip external lookup."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return True  # Treat unparseable IPs as private (safe default)


# ── GeoIP Enrichment ──────────────────────────────────────────────────────────

class GeoIPEnricher:
    """
    Provides GeoIP lookups using the MaxMind GeoLite2 City database.

    Falls back gracefully when the database file is absent (typical in dev).
    In production, download GeoLite2-City.mmdb from MaxMind and point
    GEOIP_DB_PATH at it.
    """

    def __init__(self) -> None:
        self._reader = None
        self._asn_reader = None
        self._available = False
        self._load_databases()

    def _load_databases(self) -> None:
        """Attempt to load the MaxMind databases. Non-fatal if absent."""
        try:
            import geoip2.database  # type: ignore
            if os.path.exists(settings.GEOIP_DB_PATH):
                self._reader = geoip2.database.Reader(settings.GEOIP_DB_PATH)
                self._available = True
                log.info("geoip_db_loaded", path=settings.GEOIP_DB_PATH)
            if os.path.exists(settings.GEOIP_ASN_DB_PATH):
                self._asn_reader = geoip2.database.Reader(settings.GEOIP_ASN_DB_PATH)
        except ImportError:
            log.warning("geoip2_not_installed", hint="pip install geoip2")
        except Exception as exc:
            log.warning("geoip_db_load_failed", error=str(exc))

    def lookup(self, ip: str) -> Dict[str, Any]:
        """
        Return geographic metadata for *ip*.
        Returns empty placeholders on any error.
        """
        if _is_private_ip(ip):
            return {**_EMPTY_GEO, "country": "Private", "city": "Internal Network"}

        if not self._available or not self._reader:
            return _EMPTY_GEO.copy()

        try:
            import geoip2.errors  # type: ignore
            response = self._reader.city(ip)
            result = {
                "country":      response.country.name or "Unknown",
                "country_code": response.country.iso_code or "N/A",
                "city":         response.city.name or "Unknown",
                "latitude":     float(response.location.latitude or 0),
                "longitude":    float(response.location.longitude or 0),
                "isp":          "Unknown",
                "asn":          "",
            }
            # Enrich with ASN data if available
            if self._asn_reader:
                asn_response = self._asn_reader.asn(ip)
                result["isp"] = asn_response.autonomous_system_organization or "Unknown"
                result["asn"] = f"AS{asn_response.autonomous_system_number or ''}"

            return result
        except Exception as exc:
            log.debug("geoip_lookup_failed", ip=ip, error=str(exc))
            return _EMPTY_GEO.copy()

    def close(self) -> None:
        if self._reader:
            self._reader.close()
        if self._asn_reader:
            self._asn_reader.close()


# ── Threat Intelligence Enrichment ────────────────────────────────────────────

class ThreatIntelEnricher:
    """
    Queries external Threat Intelligence sources to assess IP reputation.

    Sources:
      - AbuseIPDB  (real, requires API key)
      - VirusTotal (real, requires API key)
      - OTX        (simulated — integrate AlienVault OTX SDK for production)
      - MISP       (simulated — integrate PyMISP for production)
    """

    _TIMEOUT = 5.0  # seconds per external call

    def __init__(self) -> None:
        # Simple in-process cache: ip → (timestamp, result)
        self._cache: Dict[str, tuple[datetime, Dict]] = {}
        self._cache_ttl_seconds = 3600  # 1 hour

    def _get_cached(self, ip: str) -> Optional[Dict]:
        if ip in self._cache:
            ts, result = self._cache[ip]
            if (datetime.utcnow() - ts).seconds < self._cache_ttl_seconds:
                return result
        return None

    def _set_cache(self, ip: str, result: Dict) -> None:
        self._cache[ip] = (datetime.utcnow(), result)

    async def enrich(self, ip: str) -> Dict[str, Any]:
        """
        Concurrently query all threat intel sources and merge results.
        Cache results for 1 hour to avoid hammering free-tier APIs.
        """
        cached = self._get_cached(ip)
        if cached:
            return {**cached, "from_cache": True}

        if _is_private_ip(ip):
            return {**_EMPTY_INTEL.copy(), "note": "private_ip"}

        # Run all lookups concurrently
        abuse_task  = asyncio.create_task(self._query_abuseipdb(ip))
        vt_task     = asyncio.create_task(self._query_virustotal(ip))
        otx_task    = asyncio.create_task(self._query_otx_simulated(ip))

        results = await asyncio.gather(abuse_task, vt_task, otx_task, return_exceptions=True)
        abuse_data, vt_data, otx_data = results

        intel: Dict[str, Any] = {**_EMPTY_INTEL.copy()}

        if isinstance(abuse_data, dict):
            intel.update(abuse_data)
        if isinstance(vt_data, dict):
            intel["vt_malicious"]  = vt_data.get("vt_malicious", 0)
            intel["vt_suspicious"] = vt_data.get("vt_suspicious", 0)
        if isinstance(otx_data, dict):
            intel["otx_pulses"]    = otx_data.get("pulse_count", 0)
            if otx_data.get("pulse_count", 0) > 0:
                intel["threat_sources"].append("OTX")

        # Determine overall verdict
        intel["is_known_bad"] = (
            intel["abuse_score"] > 50
            or intel["vt_malicious"] > 3
            or intel["otx_pulses"] > 2
        )

        self._set_cache(ip, intel)
        return intel

    async def _query_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Query AbuseIPDB for IP reputation score."""
        if not settings.ABUSEIPDB_API_KEY:
            return {"abuse_score": 0, "abuse_reports": 0}
        try:
            async with httpx.AsyncClient(timeout=self._TIMEOUT) as client:
                r = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                )
                r.raise_for_status()
                data = r.json().get("data", {})
                if data.get("abuseConfidenceScore", 0) > 20:
                    return {
                        "abuse_score":   data.get("abuseConfidenceScore", 0),
                        "abuse_reports": data.get("totalReports", 0),
                        "threat_sources": ["AbuseIPDB"],
                    }
                return {"abuse_score": data.get("abuseConfidenceScore", 0), "abuse_reports": 0}
        except Exception as exc:
            log.debug("abuseipdb_query_failed", ip=ip, error=str(exc))
            return {}

    async def _query_virustotal(self, ip: str) -> Dict[str, Any]:
        """Query VirusTotal for IP analysis stats."""
        if not settings.VIRUSTOTAL_API_KEY:
            return {}
        try:
            async with httpx.AsyncClient(timeout=self._TIMEOUT) as client:
                r = await client.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                )
                r.raise_for_status()
                stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                return {
                    "vt_malicious":  stats.get("malicious", 0),
                    "vt_suspicious": stats.get("suspicious", 0),
                }
        except Exception as exc:
            log.debug("virustotal_query_failed", ip=ip, error=str(exc))
            return {}

    async def _query_otx_simulated(self, ip: str) -> Dict[str, Any]:
        """
        Simulated OTX lookup.
        Replace with:  ``OTXv2(settings.OTX_API_KEY).get_indicator_details_full(IndicatorTypes.IPv4, ip)``
        when the AlienVault OTX SDK is available.
        """
        # Simulate network latency
        await asyncio.sleep(0.05)
        # Return 0 pulses by default; a real implementation would call OTX
        return {"pulse_count": 0}


# ── Host Context Enrichment ───────────────────────────────────────────────────

class HostContextEnricher:
    """
    Provides asset criticality context for a target hostname.
    The host inventory is loaded from settings (JSON string).

    In production, replace with a CMDB API call.
    """

    def enrich(self, hostname: str) -> Dict[str, Any]:
        """Return host metadata including criticality level."""
        criticality = settings.get_host_criticality(hostname)
        return {
            "hostname":    hostname,
            "criticality": criticality,
            "is_server":   criticality in ("CRITICAL", "HIGH"),
            "criticality_score": {
                "CRITICAL": 30,
                "HIGH": 20,
                "MEDIUM": 10,
                "LOW": 0,
            }.get(criticality, 10),
        }


# ── Orchestrated Enrichment ───────────────────────────────────────────────────

class EnrichmentOrchestrator:
    """
    Combines GeoIP, Threat Intel, and Host Context into a single enrichment
    pass. Called by the Consumer worker for every alert before it is persisted.
    """

    def __init__(self) -> None:
        self.geoip      = GeoIPEnricher()
        self.threat_intel = ThreatIntelEnricher()
        self.host_ctx   = HostContextEnricher()

    async def enrich_alert(
        self,
        source_ip: Optional[str],
        target_hostname: Optional[str],
    ) -> Dict[str, Any]:
        """
        Run all enrichment sources concurrently.

        Returns a single dict with keys: ``geo``, ``intel``, ``host``.
        """
        enrichment: Dict[str, Any] = {"geo": {}, "intel": {}, "host": {}}

        if source_ip:
            # GeoIP is sync (C extension), run in executor to avoid blocking
            loop = asyncio.get_running_loop()
            geo = await loop.run_in_executor(None, self.geoip.lookup, source_ip)
            intel = await self.threat_intel.enrich(source_ip)
            enrichment["geo"]   = geo
            enrichment["intel"] = intel

        if target_hostname:
            enrichment["host"] = self.host_ctx.enrich(target_hostname)

        enrichment["enriched_at"] = datetime.utcnow().isoformat()
        return enrichment

    def close(self) -> None:
        self.geoip.close()


# Module-level singleton
enrichment_orchestrator = EnrichmentOrchestrator()
