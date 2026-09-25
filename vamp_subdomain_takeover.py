#!/usr/bin/env python3
"""
vamp_subdomain_takeover.py — Escáner de Vulnerabilidades de Subdomain Takeover
================================================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v1.0

DESCRIPCIÓN GENERAL
-------------------
Escáner especializado en la detección de vulnerabilidades de subdomain
takeover. Identifica subdominios que apuntan mediante registros CNAME a
servicios externos (GitHub Pages, AWS S3, Heroku, Netlify, Vercel, Azure,
GitLab Pages, Fastly…) donde el endpoint o bucket ya no existe y puede ser
reclamado por un atacante.

Un subdomain takeover permite a un tercero publicar contenido bajo el dominio
de la víctima sin necesitar acceso al DNS — vector de phishing, robo de
cookies de sesión, bypass de Content Security Policy o fraude de marca. Es uno
de los hallazgos de mayor impacto en auditorías web y uno de los más
frecuentemente pasados por alto.

La herramienta acepta tres modos de entrada:
  · Dominio raíz (-d domain.com): enumera subdominios automáticamente usando
    las mismas 6 fuentes OSINT que vamp-passive-recon (crt.sh, OTX,
    HackerTarget, Wayback Machine, AnubisDB, urlscan.io).
  · Fichero de subdominios (-f subdomains.txt): acepta el JSON de salida de
    vamp-passive-recon o un fichero de texto plano (uno por línea).
  · Lista directa (--subdomains sub1.dom.com,sub2.dom.com).

ARQUITECTURA DE EJECUCIÓN (3 fases)
------------------------------------
  Fase 1 — Enumeración de subdominios (opcional)
    Solo se ejecuta si se proporciona -d DOMINIO sin -f ni --subdomains.
    Consulta simultáneamente las 6 fuentes OSINT con asyncio + aiohttp.
    Resultado: set deduplicado de subdominios del dominio objetivo.

  Fase 2 — Resolución DNS y fingerprinting del servicio
    Para cada subdominio resuelve la cadena CNAME completa mediante
    dns.asyncresolver. Compara el destino final contra SERVICE_SIGNATURES
    (30+ servicios conocidos). Si hay coincidencia pasa a Fase 3.
    Subdominios sin CNAME o con CNAME a infraestructura propia → SAFE.

  Fase 3 — Verificación HTTP de takeover
    GET HTTP al subdominio con timeout configurable. Busca en el cuerpo de
    respuesta las cadenas de fingerprint específicas de cada servicio.
    · VULNERABLE  — fingerprint de "endpoint no reclamado" confirmado
    · POTENTIAL   — CNAME al servicio pero fingerprint ambiguo o sin respuesta
    · SAFE        — endpoint activo y válido (fingerprint no encontrado)

MODELO DE RIESGO
----------------
  VULNERABLE  — Takeover confirmado. CVSS estimado por servicio. Acción inmediata.
  POTENTIAL   — CNAME huérfano sin confirmación HTTP. Verificar manualmente.
  SAFE        — CNAME resuelve a endpoint activo. Sin riesgo detectado.

DEPENDENCIAS
------------
  aiohttp    >= 3.9.0    — Verificación HTTP asíncrona
  dnspython  >= 2.4.0    — Resolución DNS asíncrona (cadena CNAME)
  rich       >= 13.7.0   — Salida de consola con formato enriquecido

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from html import escape
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import aiohttp
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

try:
    import dns.asyncresolver
    import dns.exception
    import dns.rdatatype
except ImportError:
    print("[ERROR] Instala dnspython: pip install dnspython", file=sys.stderr)
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Constantes
# ─────────────────────────────────────────────────────────────────────────────

VERSION   = "1.3"
TOOL_NAME = "vamp-subdomain-takeover"

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-subdomain-takeover v1.1 · Subdomain Takeover Vulnerability Scanner
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Base de datos de firmas de servicios vulnerables
# ─────────────────────────────────────────────────────────────────────────────
# Cada entrada: clave = substring del destino CNAME
#   name        — nombre legible del servicio
#   fingerprint — cadena en el body HTTP que confirma endpoint no reclamado
#   cvss        — CVSS v3 base estimado si se confirma takeover
# ─────────────────────────────────────────────────────────────────────────────

SERVICE_SIGNATURES: Dict[str, Dict[str, str]] = {
    # Control de versiones / Pages
    "github.io":            {"name": "GitHub Pages",       "fingerprint": "There isn't a GitHub Pages site here",       "cvss": "9.0"},
    "gitlab.io":            {"name": "GitLab Pages",       "fingerprint": "404",                                        "cvss": "8.5"},
    "bitbucket.io":         {"name": "Bitbucket Pages",    "fingerprint": "Repository not found",                       "cvss": "8.0"},
    # Cloud compute / PaaS
    "herokuapp.com":        {"name": "Heroku",             "fingerprint": "No such app",                                "cvss": "8.8"},
    "azurewebsites.net":    {"name": "Azure Web App",      "fingerprint": "404 Web Site not found",                     "cvss": "8.5"},
    "cloudapp.azure.com":   {"name": "Azure CloudApp",     "fingerprint": "404 Web Site not found",                     "cvss": "8.5"},
    "trafficmanager.net":   {"name": "Azure Traffic Mgr",  "fingerprint": "404",                                        "cvss": "7.5"},
    # Almacenamiento objeto
    "s3.amazonaws.com":     {"name": "AWS S3",             "fingerprint": "NoSuchBucket",                               "cvss": "9.3"},
    "s3-website":           {"name": "AWS S3 Website",     "fingerprint": "NoSuchBucket",                               "cvss": "9.3"},
    # JAMstack / static
    "netlify.app":          {"name": "Netlify",            "fingerprint": "Not Found",                                  "cvss": "8.8"},
    "netlify.com":          {"name": "Netlify",            "fingerprint": "Not Found",                                  "cvss": "8.8"},
    "vercel.app":           {"name": "Vercel",             "fingerprint": "The deployment could not be found",          "cvss": "8.8"},
    "webflow.io":           {"name": "Webflow",            "fingerprint": "The page you are looking for doesn",         "cvss": "8.0"},
    "surge.sh":             {"name": "Surge.sh",           "fingerprint": "project not found",                          "cvss": "8.0"},
    "strikingly.com":       {"name": "Strikingly",         "fingerprint": "page not found",                             "cvss": "7.0"},
    "squarespace.com":      {"name": "Squarespace",        "fingerprint": "No Site Found",                              "cvss": "7.0"},
    "wordpress.com":        {"name": "WordPress.com",      "fingerprint": "Do you want to register",                    "cvss": "7.5"},
    "tumblr.com":           {"name": "Tumblr",             "fingerprint": "Whatever you were looking for doesn",        "cvss": "7.5"},
    "cargocollective.com":  {"name": "Cargo Collective",   "fingerprint": "404 Not Found",                              "cvss": "7.0"},
    # CDN
    "fastly.net":           {"name": "Fastly CDN",         "fingerprint": "Fastly error: unknown domain",               "cvss": "8.0"},
    "cloudfront.net":       {"name": "AWS CloudFront",     "fingerprint": "ERROR: The request could not be satisfied",  "cvss": "8.5"},
    "pantheonsite.io":      {"name": "Pantheon",           "fingerprint": "The gods are wise, but they do not know",    "cvss": "7.5"},
    "getpantheon.com":      {"name": "Pantheon",           "fingerprint": "The gods are wise, but they do not know",    "cvss": "7.5"},
    # Ecommerce
    "myshopify.com":        {"name": "Shopify",            "fingerprint": "Sorry, this shop is currently unavailable",  "cvss": "7.0"},
    # CMS / Blogging
    "ghost.io":             {"name": "Ghost",              "fingerprint": "The thing you were looking for is no longer here", "cvss": "7.5"},
    "readme.io":            {"name": "ReadMe.io",          "fingerprint": "Project doesnt exist",                       "cvss": "7.5"},
    "readthedocs.io":       {"name": "ReadTheDocs",        "fingerprint": "unknown to Read the Docs",                   "cvss": "7.5"},
    # Helpdesk / CRM
    "freshdesk.com":        {"name": "Freshdesk",          "fingerprint": "There is no helpdesk here",                  "cvss": "7.0"},
    "zendesk.com":          {"name": "Zendesk",            "fingerprint": "Help Center Closed",                         "cvss": "7.0"},
    "helpscoutdocs.com":    {"name": "HelpScout",          "fingerprint": "No settings were found for this company",    "cvss": "7.0"},
    # Monitorización / Status
    "statuspage.io":        {"name": "Statuspage.io",      "fingerprint": "You are being redirected",                   "cvss": "7.0"},
}

# ─────────────────────────────────────────────────────────────────────────────
# Modelos de datos
# ─────────────────────────────────────────────────────────────────────────────

class TakeoverStatus(str, Enum):
    VULNERABLE = "VULNERABLE"
    POTENTIAL  = "POTENTIAL"
    SAFE       = "SAFE"
    ERROR      = "ERROR"


@dataclass
class SubdomainResult:
    """Resultado del análisis de un subdominio."""
    subdomain:    str
    cname_chain:  List[str]          = field(default_factory=list)
    service:      Optional[str]      = None
    service_key:  Optional[str]      = None
    cvss:         Optional[str]      = None
    status:       TakeoverStatus     = TakeoverStatus.SAFE
    http_status:  Optional[int]      = None
    fingerprint_found: bool          = False
    error:        Optional[str]      = None
    # v1.1: hallazgos NS/MX takeover
    ns_issues:    List[str]          = field(default_factory=list)
    mx_issues:    List[str]          = field(default_factory=list)
    # v1.1: fingerprint de servicio no reclamado confirmado vía urllib.request
    takeover_confirmed_body: bool    = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


# ─────────────────────────────────────────────────────────────────────────────
# Fase 1 — Enumeración OSINT de subdominios
# ─────────────────────────────────────────────────────────────────────────────

class SubdomainEnumerator:
    """
    Enumera subdominios de un dominio raíz usando 6 fuentes OSINT públicas.
    No envía tráfico al objetivo; solo consulta terceros.
    """

    UA = f"VampSecureLabs-SubdomainTakeover/{VERSION}"

    def __init__(self, domain: str, timeout: int = 20) -> None:
        self.domain  = domain
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def _crtsh(self, session: aiohttp.ClientSession) -> Set[str]:
        """Certificate Transparency logs (crt.sh)."""
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            async with session.get(url) as r:
                if r.status != 200:
                    return set()
                data = await r.json(content_type=None)
                subs: Set[str] = set()
                for entry in data:
                    for name in entry.get("name_value", "").splitlines():
                        name = name.strip().lstrip("*.")
                        if name.endswith(self.domain):
                            subs.add(name)
                return subs
        except Exception:
            return set()

    async def _otx(self, session: aiohttp.ClientSession) -> Set[str]:
        """AlienVault OTX Passive DNS."""
        try:
            key = os.environ.get("OTX_API_KEY", "")
            headers = {"X-OTX-API-KEY": key} if key else {}
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            async with session.get(url, headers=headers) as r:
                if r.status != 200:
                    return set()
                data = await r.json()
                return {
                    e["hostname"] for e in data.get("passive_dns", [])
                    if e.get("hostname", "").endswith(self.domain)
                }
        except Exception:
            return set()

    async def _hackertarget(self, session: aiohttp.ClientSession) -> Set[str]:
        """HackerTarget hostsearch."""
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            async with session.get(url) as r:
                text = await r.text()
                subs: Set[str] = set()
                for line in text.splitlines():
                    parts = line.split(",")
                    if parts and parts[0].endswith(self.domain):
                        subs.add(parts[0].strip())
                return subs
        except Exception:
            return set()

    async def _wayback(self, session: aiohttp.ClientSession) -> Set[str]:
        """Internet Archive (Wayback Machine CDX API)."""
        try:
            url = (
                f"http://web.archive.org/cdx/search/cdx"
                f"?url=*.{self.domain}&output=text&fl=original&collapse=urlkey&limit=500"
            )
            async with session.get(url) as r:
                text = await r.text()
                subs: Set[str] = set()
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    host = line.split("/")[2] if "//" in line else line.split("/")[0]
                    host = host.split(":")[0]
                    if host.endswith(self.domain):
                        subs.add(host)
                return subs
        except Exception:
            return set()

    async def _anubisdb(self, session: aiohttp.ClientSession) -> Set[str]:
        """AnubisDB (jldc.me) Passive DNS."""
        try:
            url = f"https://jldc.me/anubis/subdomains/{self.domain}"
            async with session.get(url) as r:
                data = await r.json(content_type=None)
                if isinstance(data, list):
                    return {s for s in data if isinstance(s, str) and s.endswith(self.domain)}
                return set()
        except Exception:
            return set()

    async def _urlscan(self, session: aiohttp.ClientSession) -> Set[str]:
        """urlscan.io search."""
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=100"
            async with session.get(url) as r:
                data = await r.json()
                return {
                    r_["task"]["domain"]
                    for r_ in data.get("results", [])
                    if r_.get("task", {}).get("domain", "").endswith(self.domain)
                }
        except Exception:
            return set()

    async def enumerate(self) -> Set[str]:
        """Lanza todas las fuentes en paralelo y retorna el set deduplicado."""
        connector = aiohttp.TCPConnector(ssl=False)
        headers   = {"User-Agent": self.UA}
        async with aiohttp.ClientSession(
            connector=connector, headers=headers, timeout=self.timeout
        ) as session:
            results = await asyncio.gather(
                self._crtsh(session),
                self._otx(session),
                self._hackertarget(session),
                self._wayback(session),
                self._anubisdb(session),
                self._urlscan(session),
                return_exceptions=True,
            )
        merged: Set[str] = set()
        for r in results:
            if isinstance(r, set):
                merged.update(r)
        # Excluir el dominio raíz en sí mismo
        merged.discard(self.domain)
        return merged


# ─────────────────────────────────────────────────────────────────────────────
# Fase 2+3 — Resolución DNS y verificación HTTP
# ─────────────────────────────────────────────────────────────────────────────

class TakeoverScanner:
    """
    Escanea subdominios en busca de vulnerabilidades de takeover.

    Fase 2: resuelve la cadena CNAME completa y la cruza contra
    SERVICE_SIGNATURES para detectar servicios externos potencialmente
    reclamables.

    Fase 3: verifica HTTP que el fingerprint de "endpoint no reclamado"
    esté presente en el body de respuesta.
    """

    HTTP_TIMEOUT = aiohttp.ClientTimeout(total=12)
    DNS_TIMEOUT  = 6.0
    CONCURRENCY  = 30

    UA = f"VampSecureLabs-SubdomainTakeover/{VERSION}"

    def __init__(self, concurrency: int = 30, http_timeout: int = 12, verify: bool = True) -> None:
        self.sem          = asyncio.Semaphore(concurrency)
        self.http_timeout = aiohttp.ClientTimeout(total=http_timeout)
        # Si verify=False se omite la verificación HTTP activa (solo análisis DNS pasivo)
        self.verify       = verify

    # ── DNS ──────────────────────────────────────────────────────────────────

    async def _resolve_cname_chain(self, subdomain: str) -> List[str]:
        """
        Sigue la cadena CNAME de un subdominio hasta el destino final.
        Retorna lista de registros CNAME en orden (vacía si no hay CNAME).
        """
        chain: List[str] = []
        current = subdomain
        seen: Set[str] = set()

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout  = self.DNS_TIMEOUT
        resolver.lifetime = self.DNS_TIMEOUT

        for _ in range(10):  # límite de profundidad anti-loop
            if current in seen:
                break
            seen.add(current)
            try:
                answer = await resolver.resolve(current, "CNAME")
                target = str(answer[0].target).rstrip(".")
                chain.append(target)
                current = target
            except (dns.exception.DNSException, Exception):
                break

        return chain

    def _match_service(self, cname_chain: List[str]) -> Optional[Tuple[str, str]]:
        """
        Busca el primer servicio conocido en la cadena CNAME.
        Retorna (service_key, service_name) o None.
        """
        for cname in cname_chain:
            cname_lower = cname.lower()
            for key, info in SERVICE_SIGNATURES.items():
                if key in cname_lower:
                    return key, info["name"]
        return None

    # ── HTTP ─────────────────────────────────────────────────────────────────

    async def _verify_http(
        self,
        subdomain: str,
        service_key: str,
        session: aiohttp.ClientSession,
    ) -> Tuple[Optional[int], bool]:
        """
        Realiza GET HTTP al subdominio y busca el fingerprint del servicio.
        Retorna (http_status, fingerprint_found).
        """
        fingerprint = SERVICE_SIGNATURES[service_key]["fingerprint"]
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                async with session.get(url, allow_redirects=True, ssl=False) as resp:
                    body = await resp.text(encoding="utf-8", errors="replace")
                    found = fingerprint.lower() in body.lower()
                    return resp.status, found
            except aiohttp.ClientConnectorError:
                continue
            except Exception:
                return None, False
        return None, False

    # ── Orquestador por subdominio ────────────────────────────────────────────

    async def _scan_one(
        self,
        subdomain: str,
        session: aiohttp.ClientSession,
    ) -> SubdomainResult:
        """
        Ejecuta las fases de análisis para un subdominio.

        Fases ejecutadas (v1.1):
          2a — Resolución CNAME + fingerprinting de servicio
          2b — NS takeover check (ns_issues)
          2c — MX takeover check (mx_issues)
          3  — Verificación HTTP fingerprint (aiohttp + urllib.request)
        """
        async with self.sem:
            result = SubdomainResult(subdomain=subdomain)

            # Fases 2b y 2c: NS/MX takeover checks (en paralelo con CNAME)
            await asyncio.gather(
                self._check_ns_takeover(subdomain, result),
                self._check_mx_takeover(subdomain, result),
                return_exceptions=True,
            )

            # Fase 2a — DNS CNAME + fingerprinting de servicio
            try:
                chain = await self._resolve_cname_chain(subdomain)
            except Exception as exc:
                result.error  = str(exc)
                result.status = TakeoverStatus.ERROR
                return result

            result.cname_chain = chain
            if not chain:
                # Sin CNAME → SAFE para takeover CNAME, pero puede tener NS/MX issues
                return result

            match = self._match_service(chain)
            if not match:
                return result  # CNAME a dominio propio o desconocido → SAFE

            service_key, service_name = match
            result.service_key = service_key
            result.service     = service_name
            result.cvss        = SERVICE_SIGNATURES[service_key]["cvss"]

            if not self.verify:
                # Con --no-verify: clasificar como POTENTIAL sin realizar peticiones HTTP
                result.status = TakeoverStatus.POTENTIAL
                return result

            # Fase 3a — Verificación HTTP con aiohttp (fingerprint de servicio específico)
            http_status, fingerprint_found = await self._verify_http(
                subdomain, service_key, session
            )
            result.http_status       = http_status
            result.fingerprint_found = fingerprint_found

            if fingerprint_found:
                result.status = TakeoverStatus.VULNERABLE
            elif http_status is None:
                result.status = TakeoverStatus.POTENTIAL
            else:
                result.status = TakeoverStatus.POTENTIAL if http_status >= 400 else TakeoverStatus.SAFE

            # Fase 3b — Verificación adicional con fingerprints genéricos (urllib.request)
            # Solo si el CNAME apunta a un servicio cloud conocido y aún no está confirmado
            if result.status in (TakeoverStatus.POTENTIAL, TakeoverStatus.SAFE):
                await self._verify_takeover_fingerprints(subdomain, result)

            return result

    # ── NS takeover checks (v1.1) ─────────────────────────────────────────

    # Patrones de nameservers de registradores cloud conocidos
    _NS_CLOUD_PATTERNS = ["awsdns", "azure-dns.com", "googledomains.com", "ns.cloudflare.com"]
    # SaaS de correo que permiten reclamar dominios
    _MX_SAAS_PATTERNS  = ["mailchimp", "sendgrid", "mailgun", "sparkpost", "mandrillapp"]

    async def _check_ns_takeover(
        self,
        domain: str,
        result: SubdomainResult,
    ) -> None:
        """
        Consulta los registros NS del subdominio y detecta posibles NS takeover.

        Verifica dos condiciones:
          1. NS apunta a un dominio que devuelve NXDOMAIN (nameserver no registrado).
          2. NS usa un proveedor cloud conocido (AWS Route53, Azure, GCP).

        Los hallazgos se acumulan en result.ns_issues.
        """
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout  = self.DNS_TIMEOUT
        resolver.lifetime = self.DNS_TIMEOUT

        try:
            answer = await resolver.resolve(domain, "NS")
            ns_records = [str(rr.target).rstrip(".") for rr in answer]
        except (dns.exception.DNSException, Exception):
            return   # Sin registros NS o error: no hay nada que analizar

        for ns in ns_records:
            ns_lower = ns.lower()

            # Detectar proveedor cloud conocido
            for patron in self._NS_CLOUD_PATTERNS:
                if patron in ns_lower:
                    result.ns_issues.append(
                        f"NS usa proveedor cloud ({patron}): {ns}"
                    )
                    break

            # Verificar si el dominio del NS resuelve (detectar NS takeover)
            try:
                await resolver.resolve(ns, "A")
            except dns.resolver.NXDOMAIN:
                result.ns_issues.append(
                    f"HIGH: NS takeover potencial — nameserver apunta a dominio "
                    f"no registrado: {ns}"
                )
            except (dns.exception.DNSException, Exception):
                pass   # Error de red u otro: no concluyente

    async def _check_mx_takeover(
        self,
        domain: str,
        result: SubdomainResult,
    ) -> None:
        """
        Consulta los registros MX del subdominio y detecta posibles MX takeover.

        Verifica dos condiciones:
          1. El dominio del servidor MX no resuelve (NXDOMAIN → MX takeover).
          2. El MX apunta a un SaaS de correo que permite reclamar dominios
             (Mailchimp, SendGrid, etc.).

        Los hallazgos se acumulan en result.mx_issues.
        """
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout  = self.DNS_TIMEOUT
        resolver.lifetime = self.DNS_TIMEOUT

        try:
            answer = await resolver.resolve(domain, "MX")
            mx_records = [str(rr.exchange).rstrip(".") for rr in answer]
        except (dns.exception.DNSException, Exception):
            return   # Sin registros MX o error

        for mx in mx_records:
            mx_lower = mx.lower()

            # Detectar SaaS de correo con posibilidad de reclamación
            for patron in self._MX_SAAS_PATTERNS:
                if patron in mx_lower:
                    result.mx_issues.append(
                        f"MEDIUM: MX apunta a proveedor SaaS ({patron}) — "
                        f"verificar ownership del dominio: {mx}"
                    )
                    break

            # Verificar si el dominio del MX resuelve
            try:
                await resolver.resolve(mx, "A")
            except dns.resolver.NXDOMAIN:
                result.mx_issues.append(
                    f"HIGH: MX takeover potencial — servidor de correo apunta a "
                    f"dominio no registrado: {mx}"
                )
            except (dns.exception.DNSException, Exception):
                pass   # Error de red: no concluyente

    # ── Verificación de fingerprints de takeover con urllib.request (v1.1) ──

    # Fingerprints de "endpoint no reclamado" por servicio
    _TAKEOVER_FINGERPRINTS: List[str] = [
        "There isn't a GitHub Pages site here",
        "No such app",
        "Application error",                          # Heroku: app caída pero nombre libre
        "herokucdn.com/error-pages/no-such-app.html",
        "NoSuchBucket",
        "The specified bucket does not exist",         # AWS S3: bucket eliminado
        "Not Found - Request ID",
        "Microsoft Azure - 404 Web Site Not Found",
        "404 Web Site not found",
        "ERROR: The request could not be satisfied",   # AWS CloudFront: distribución no reclamada
        "Sorry, this shop is currently unavailable",
        "The deployment could not be found",
        "project not found",
        "Repository not found",
        "Page Not Found",
        "Fastly error: unknown domain",
        "There is no helpdesk here",
        "Help Center Closed",
        "unknown to Read the Docs",
        "The gods are wise, but they do not know",
        "Do you want to register",
        "Project doesnt exist",
    ]

    async def _verify_takeover_fingerprints(
        self,
        subdomain: str,
        result: SubdomainResult,
    ) -> None:
        """
        Verificación pasiva de takeover para subdominios con CNAME a servicios cloud.

        Realiza GET al subdominio con urllib.request (timeout 10 s) y busca
        fingerprints de "dominio/endpoint no reclamado" en el cuerpo de respuesta.

        Si coincide algún fingerprint, marca result.takeover_confirmed_body = True
        y establece result.status = VULNERABLE (CRITICAL).

        Se ejecuta como tarea bloqueante en un ThreadPoolExecutor para no
        bloquear el bucle asyncio.
        """
        import urllib.request as _ureq
        import urllib.error  as _uerr

        def _fetch_blocking(url: str) -> str:
            """Descarga el cuerpo del subdominio de forma bloqueante."""
            try:
                req = _ureq.Request(
                    url,
                    headers={"User-Agent": self.UA},
                )
                with _ureq.urlopen(req, timeout=10) as resp:
                    raw = resp.read(32768)   # Leer hasta 32 KB
                    return raw.decode("utf-8", errors="replace")
            except (_uerr.URLError, Exception):
                return ""

        body = ""
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                body = await asyncio.get_event_loop().run_in_executor(
                    None, _fetch_blocking, url
                )
            except Exception:
                continue
            if body:
                break

        if not body:
            return

        body_lower = body.lower()
        for fp in self._TAKEOVER_FINGERPRINTS:
            if fp.lower() in body_lower:
                result.takeover_confirmed_body = True
                result.fingerprint_found       = True
                result.status                  = TakeoverStatus.VULNERABLE
                break

    async def scan(self, subdomains: Set[str]) -> List[SubdomainResult]:
        """Escanea todos los subdominios en paralelo."""
        connector = aiohttp.TCPConnector(ssl=False, limit=self.sem._value)
        async with aiohttp.ClientSession(
            connector=connector,
            headers={"User-Agent": self.UA},
            timeout=self.http_timeout,
        ) as session:
            tasks = [self._scan_one(sub, session) for sub in sorted(subdomains)]
            return await asyncio.gather(*tasks)


# ─────────────────────────────────────────────────────────────────────────────
# Salida Rich — tabla en vivo y resumen final
# ─────────────────────────────────────────────────────────────────────────────

_STATUS_STYLE: Dict[TakeoverStatus, str] = {
    TakeoverStatus.VULNERABLE: "bold red",
    TakeoverStatus.POTENTIAL:  "bold yellow",
    TakeoverStatus.SAFE:       "dim green",
    TakeoverStatus.ERROR:      "dim",
}

_STATUS_ICON: Dict[TakeoverStatus, str] = {
    TakeoverStatus.VULNERABLE: "🔴 VULNERABLE",
    TakeoverStatus.POTENTIAL:  "🟡 POTENTIAL",
    TakeoverStatus.SAFE:       "🟢 SAFE",
    TakeoverStatus.ERROR:      "⚪ ERROR",
}


def _build_results_table(results: List[SubdomainResult]) -> Table:
    table = Table(
        title="Resultados — Subdomain Takeover Scan",
        show_header=True,
        header_style="bold cyan",
        border_style="bright_black",
        expand=True,
    )
    table.add_column("Subdominio",  style="white",       no_wrap=True, max_width=45)
    table.add_column("Servicio",    style="cyan",        no_wrap=True, max_width=18)
    table.add_column("CNAME →",     style="bright_black", no_wrap=True, max_width=35)
    table.add_column("HTTP",        style="white",       no_wrap=True, max_width=6,  justify="right")
    table.add_column("CVSS",        style="white",       no_wrap=True, max_width=5,  justify="right")
    table.add_column("Estado",      no_wrap=True,        max_width=16)

    for r in sorted(results, key=lambda x: (x.status.value, x.subdomain)):
        style    = _STATUS_STYLE[r.status]
        label    = _STATUS_ICON[r.status]
        cname    = r.cname_chain[-1] if r.cname_chain else "—"
        http_str = str(r.http_status) if r.http_status else "—"
        cvss_str = r.cvss or "—"

        table.add_row(
            r.subdomain,
            r.service or "—",
            cname,
            http_str,
            cvss_str,
            Text(label, style=style),
        )

    return table


def _print_vuln_panels(results: List[SubdomainResult]) -> None:
    """Imprime un panel de alerta detallado por cada hallazgo VULNERABLE."""
    vulns = [r for r in results if r.status == TakeoverStatus.VULNERABLE]
    if not vulns:
        return

    console.print()
    console.print("[bold red]── HALLAZGOS CRÍTICOS ──────────────────────────────────────────────────────[/]")
    for r in vulns:
        fingerprint = SERVICE_SIGNATURES[r.service_key]["fingerprint"]
        body = (
            f"[bold white]Subdominio:[/]    {r.subdomain}\n"
            f"[bold white]Servicio:[/]      {r.service}\n"
            f"[bold white]CNAME chain:[/]   {' → '.join(r.cname_chain)}\n"
            f"[bold white]HTTP status:[/]   {r.http_status}\n"
            f"[bold white]Fingerprint:[/]   [yellow]{fingerprint}[/]\n"
            f"[bold white]CVSS estimado:[/] [red]{r.cvss}[/]\n\n"
            f"[dim]Acción: Verificar la reclamación del endpoint externo o eliminar el\n"
            f"registro CNAME del DNS si el servicio ya no se usa.[/]"
        )
        console.print(Panel(body, title=f"[bold red]⚠ TAKEOVER CONFIRMADO: {r.subdomain}[/]",
                            border_style="red"))


# ─────────────────────────────────────────────────────────────────────────────
# Exportación JSON
# ─────────────────────────────────────────────────────────────────────────────

def _export_json(results: List[SubdomainResult], path: str) -> None:
    """Exporta los resultados completos a JSON."""
    output = {
        "tool":      TOOL_NAME,
        "version":   VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total":      len(results),
            "vulnerable": sum(1 for r in results if r.status == TakeoverStatus.VULNERABLE),
            "potential":  sum(1 for r in results if r.status == TakeoverStatus.POTENTIAL),
            "safe":       sum(1 for r in results if r.status == TakeoverStatus.SAFE),
        },
        "results": [r.to_dict() for r in results],
    }
    Path(path).write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[dim]  JSON → {path}[/]")


# ─────────────────────────────────────────────────────────────────────────────
# Exportación HTML dark-theme
# ─────────────────────────────────────────────────────────────────────────────

_STATUS_COLOR = {
    "VULNERABLE": "#ff4444",
    "POTENTIAL":  "#f0c040",
    "SAFE":       "#4caf50",
    "ERROR":      "#555",
}


def _export_html(results: List[SubdomainResult], domain: str, path: str) -> None:
    """Genera informe HTML standalone dark-theme."""
    now    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    vulns  = [r for r in results if r.status == TakeoverStatus.VULNERABLE]
    pots   = [r for r in results if r.status == TakeoverStatus.POTENTIAL]
    safes  = [r for r in results if r.status == TakeoverStatus.SAFE]
    errors = [r for r in results if r.status == TakeoverStatus.ERROR]

    def rows(subset: List[SubdomainResult]) -> str:
        out = []
        for r in subset:
            color = _STATUS_COLOR.get(r.status.value, "#aaa")
            cname = escape(r.cname_chain[-1]) if r.cname_chain else "—"
            svc   = escape(r.service or "—")
            http  = str(r.http_status) if r.http_status else "—"
            cvss  = r.cvss or "—"
            out.append(
                f'<tr>'
                f'<td>{escape(r.subdomain)}</td>'
                f'<td>{svc}</td>'
                f'<td class="mono">{cname}</td>'
                f'<td>{http}</td>'
                f'<td>{cvss}</td>'
                f'<td style="color:{color};font-weight:bold">{r.status.value}</td>'
                f'</tr>'
            )
        return "\n".join(out)

    all_sorted = sorted(results, key=lambda x: (x.status.value, x.subdomain))

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>VampSecure Labs — Subdomain Takeover Report — {escape(domain)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#010101;color:#ccc;font-family:"Share Tech Mono",monospace;font-size:13px;padding:30px}}
  h1{{color:#9d00ff;font-size:1.6rem;margin-bottom:4px}}
  .meta{{color:#444;font-size:.75rem;margin-bottom:30px}}
  .summary{{display:flex;gap:24px;margin-bottom:30px}}
  .kpi{{background:#0f0f0f;border:1px solid #222;padding:14px 22px;text-align:center}}
  .kpi-n{{font-size:2rem;font-weight:bold}}
  .kpi-l{{font-size:.7rem;color:#555;letter-spacing:1px}}
  .vuln-n{{color:#ff4444}}.pot-n{{color:#f0c040}}.safe-n{{color:#4caf50}}.tot-n{{color:#00f2ff}}
  h2{{color:#00f2ff;font-size:1rem;margin:28px 0 10px;border-left:4px solid #9d00ff;padding-left:12px}}
  table{{width:100%;border-collapse:collapse;font-size:.78rem}}
  th{{background:#111;color:#9d00ff;text-align:left;padding:8px;border-bottom:2px solid #222}}
  td{{padding:7px 8px;border-bottom:1px solid #111}}
  tr:hover{{background:#0a0a0a}}
  .mono{{color:#888;font-size:.72rem}}
  footer{{margin-top:40px;color:#333;font-size:.7rem;border-top:1px solid #111;padding-top:12px}}
</style>
</head>
<body>
<h1>VampSecure Labs — Subdomain Takeover Scan</h1>
<div class="meta">{escape(domain)} · {now} · vamp-subdomain-takeover v{VERSION}</div>

<div class="summary">
  <div class="kpi"><div class="kpi-n tot-n">{len(results)}</div><div class="kpi-l">TOTAL</div></div>
  <div class="kpi"><div class="kpi-n vuln-n">{len(vulns)}</div><div class="kpi-l">VULNERABLE</div></div>
  <div class="kpi"><div class="kpi-n pot-n">{len(pots)}</div><div class="kpi-l">POTENTIAL</div></div>
  <div class="kpi"><div class="kpi-n safe-n">{len(safes)}</div><div class="kpi-l">SAFE</div></div>
  <div class="kpi"><div class="kpi-n" style="color:#555">{len(errors)}</div><div class="kpi-l">ERROR</div></div>
</div>

<h2>Todos los resultados</h2>
<table>
  <thead><tr><th>Subdominio</th><th>Servicio</th><th>CNAME destino</th><th>HTTP</th><th>CVSS</th><th>Estado</th></tr></thead>
  <tbody>{rows(all_sorted)}</tbody>
</table>

<footer>
  © VampSecure Studios — VampSecure Labs Security Research Division<br>
  Uso exclusivo en entornos autorizados. Los datos son confidenciales.
</footer>
</body>
</html>"""

    Path(path).write_text(html, encoding="utf-8")
    console.print(f"[dim]  HTML → {path}[/]")


# ─────────────────────────────────────────────────────────────────────────────
# Carga de subdominios desde fichero
# ─────────────────────────────────────────────────────────────────────────────

def _load_from_file(path: str) -> Set[str]:
    """
    Carga subdominios desde:
    · JSON de salida de vamp-passive-recon (campo "subdomains" o lista directa)
    · Texto plano (uno por línea)
    """
    content = Path(path).read_text(encoding="utf-8").strip()
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return {s for s in data if isinstance(s, str) and s}
        if isinstance(data, dict):
            subs: Set[str] = set()
            for key in ("subdomains", "results", "hosts"):
                val = data.get(key)
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, str):
                            subs.add(item)
                        elif isinstance(item, dict):
                            sub = item.get("subdomain") or item.get("host") or item.get("name")
                            if sub:
                                subs.add(sub)
            return subs
    except json.JSONDecodeError:
        pass
    # Texto plano
    return {line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")}


# ─────────────────────────────────────────────────────────────────────────────
# Modo monitor — polling continuo (v1.3)
# ─────────────────────────────────────────────────────────────────────────────

async def _ejecutar_scan(args) -> List[dict]:
    """
    Ejecuta el scan completo (enumeración + DNS + HTTP) y retorna la lista de
    resultados como dicts con id, subdomain y severity. Se usa en el modo monitor.
    """
    subdomains: Set[str] = set()

    if args.subdomains:
        subdomains = {s.strip() for s in args.subdomains.split(",") if s.strip()}

    if getattr(args, "from_file", None):
        loaded = _load_from_file(args.from_file)
        subdomains.update(loaded)

    if not subdomains:
        enumerator = SubdomainEnumerator(args.domain)
        subdomains = await enumerator.enumerate()

    if not subdomains:
        return []

    scanner = TakeoverScanner(
        concurrency=args.concurrency,
        http_timeout=args.http_timeout,
        verify=not args.no_verify,
    )
    results: List[SubdomainResult] = await scanner.scan(subdomains)

    return [
        {
            "id":        r.subdomain,
            "subdomain": r.subdomain,
            "severity":  r.status.value,
            "service":   r.service or "",
        }
        for r in results
    ]


async def run_monitor_mode(dominio: str, intervalo: int, args) -> None:
    """
    Polling continuo de DNS. Detecta nuevos subdominios/cambios de takeover.
    Persiste el estado entre ciclos en ~/.config/vampsec/takeover-<dominio>.json.
    Sale con Ctrl+C.
    """
    state_file = (
        Path.home() / ".config" / "vampsec"
        / f"takeover-{dominio.replace('.', '_')}.json"
    )
    state_file.parent.mkdir(parents=True, exist_ok=True)

    # Cargar estado previo (dict {id: hallazgo})
    estado_prev: dict = {}
    if state_file.exists():
        try:
            estado_prev = json.loads(state_file.read_text())
        except Exception:
            pass

    console.print(f"[bold]Modo monitor activo — intervalo {intervalo}s — Ctrl+C para salir[/]")

    while True:
        try:
            # Ejecutar el scan completo
            resultados = await _ejecutar_scan(args)

            # Detectar cambios: nuevos hallazgos o resueltos
            nuevos    = [h for h in resultados if h["id"] not in estado_prev]
            resueltos = [h_id for h_id in estado_prev
                         if h_id not in {h["id"] for h in resultados}]

            if nuevos:
                console.print(f"[red bold]⚠ {len(nuevos)} nuevo(s) hallazgo(s)[/]")
                for h in nuevos:
                    console.print(
                        f"  [red]+ {h.get('subdomain','?')} → "
                        f"{h.get('severity','?')} {h.get('id','?')}[/]"
                    )
            if resueltos:
                console.print(f"[green]✔ {len(resueltos)} resuelto(s)[/]")
            if not nuevos and not resueltos:
                console.print(f"[dim]Sin cambios — {len(resultados)} subdominios activos[/]")

            # Guardar estado actual
            estado_prev = {h["id"]: h for h in resultados}
            state_file.write_text(
                json.dumps(estado_prev, indent=2, ensure_ascii=False)
            )

            console.print(
                f"[dim]Próximo check en {intervalo}s "
                f"({datetime.now().strftime('%H:%M:%S')})[/]"
            )
            await asyncio.sleep(intervalo)

        except KeyboardInterrupt:
            console.print("[yellow]Monitor detenido.[/]")
            break


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="vamp-subdomain-takeover",
        description="VampSecure Labs — Escáner de Subdomain Takeover",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  # Enumerar + escanear desde dominio raíz\n"
            "  python vamp_subdomain_takeover.py -d ejemplo.com\n\n"
            "  # Cargar subdominios del JSON de vamp-passive-recon\n"
            "  python vamp_subdomain_takeover.py -d ejemplo.com -f passive_recon.json\n\n"
            "  # Lista directa con salida completa\n"
            "  python vamp_subdomain_takeover.py -d ejemplo.com \\\n"
            "    --subdomains blog.ejemplo.com,api.ejemplo.com \\\n"
            "    -o resultado.json --html resultado.html\n"
        ),
    )
    inp = p.add_argument_group("Entrada")
    inp.add_argument("-d", "--domain",     metavar="DOMINIO",  required=True,
                     help="Dominio objetivo (requerido siempre)")
    inp.add_argument("-f", "--from-file",  metavar="FICHERO",
                     help="Fichero de subdominios (JSON de passive-recon o texto plano)")
    inp.add_argument("--subdomains",       metavar="SUB1,SUB2",
                     help="Lista de subdominios separada por comas")
    out = p.add_argument_group("Salida")
    out.add_argument("-o", "--output",     metavar="FICHERO",
                     help="Exportar resultados a JSON")
    out.add_argument("--html",             metavar="FICHERO",
                     help="Exportar informe HTML dark-theme")
    out.add_argument("--only-vulnerable",  action="store_true",
                     help="Mostrar solo hallazgos VULNERABLE y POTENTIAL")
    perf = p.add_argument_group("Rendimiento")
    perf.add_argument("--concurrency",     type=int, default=30, metavar="N",
                      help="Peticiones paralelas (default: 30)")
    perf.add_argument("--http-timeout",    type=int, default=12, metavar="SEG",
                      help="Timeout HTTP en segundos (default: 12)")
    perf.add_argument("--no-verify",       action="store_true", default=False,
                      help="Omitir verificación HTTP activa; clasificar como POTENTIAL "
                           "todos los CNAME que apuntan a servicios conocidos (solo análisis DNS).")
    perf.add_argument("--monitor",         metavar="SEGUNDOS", type=int, default=0,
                      help="Polling continuo: re-escanear cada N segundos y alertar de cambios")

    # Argumentos de informe unificado VSL (--client, --engagement, --auditor,
    # --report-scope, --report-html, --report-pdf)
    from vampsec_report import add_report_args
    add_report_args(p)

    return p.parse_args()


# =============================================================================
# CONVERSOR A FORMATO DE INFORME UNIFICADO VSL
# =============================================================================

def _findings_vsl(results: List["SubdomainResult"], domain: str) -> list:
    """
    Convierte los resultados del escáner de takeover al formato Finding unificado
    de VampSecure Labs.

    Solo se incluyen subdominios con estado VULNERABLE (CRITICAL) o POTENTIAL (HIGH).
    Los subdominios SAFE y ERROR se omiten del informe de cliente.

    Parámetros
    ----------
    results : List[SubdomainResult]  — Lista de resultados del escáner
    domain  : str                    — Dominio raíz auditado

    Retorna
    -------
    List[Finding]  — Lista de hallazgos en formato VSL con prefijo SDT-NNN
    """
    from vampsec_report import Finding as VSLFinding

    ESTADOS_INCLUIDOS = {TakeoverStatus.VULNERABLE, TakeoverStatus.POTENTIAL}
    hallazgos: list = []
    n = 0

    for r in sorted(results, key=lambda x: (0 if x.status == TakeoverStatus.VULNERABLE else 1, x.subdomain)):
        if r.status not in ESTADOS_INCLUIDOS:
            continue
        n += 1

        # Severidad según nivel de confirmación
        severidad = "CRITICAL" if r.status == TakeoverStatus.VULNERABLE else "HIGH"

        # Cadena CNAME para la evidencia
        cname_str = " → ".join(r.cname_chain) if r.cname_chain else "—"

        partes_evidencia = [
            f"Estado: {r.status.value}",
            f"CNAME chain: {cname_str}",
        ]
        if r.service:
            partes_evidencia.append(f"Servicio: {r.service}")
        if r.http_status is not None:
            partes_evidencia.append(f"HTTP: {r.http_status}")
        if r.fingerprint_found:
            partes_evidencia.append("Fingerprint de takeover CONFIRMADO")
        if r.cvss:
            partes_evidencia.append(f"CVSS estimado: {r.cvss}")

        servicio_txt = r.service or "servicio externo"
        hallazgos.append(VSLFinding(
            id          = f"SDT-{n:03d}",
            title       = (
                f"Subdomain Takeover {'confirmado' if r.status == TakeoverStatus.VULNERABLE else 'potencial'}"
                f" — {r.subdomain}"
            ),
            severity    = severidad,
            description = (
                f"El subdominio '{r.subdomain}' (dominio raíz: {domain}) tiene un registro CNAME "
                f"apuntando a {cname_str} ({servicio_txt}) cuyo recurso no está reclamado. "
                "Un atacante puede registrar el recurso en el servicio destino y servir contenido "
                "bajo el dominio legítimo de la organización."
            ),
            evidence    = " | ".join(partes_evidencia),
            affected    = r.subdomain,
            remediation = (
                f"Opción A: Eliminar el registro CNAME de '{r.subdomain}' si el subdominio ya no se usa. "
                f"Opción B: Reclamar o renovar el recurso en {servicio_txt} para que el CNAME "
                "apunte a un recurso activo y controlado por la organización."
            ),
            cvss        = float(r.cvss) if r.cvss else None,
            tags        = ["dns", "subdomain-takeover", r.status.value.lower()],
        ))

    # ── Hallazgos NS takeover (v1.1) ──
    for r in results:
        if not r.ns_issues:
            continue
        for issue in r.ns_issues:
            if not issue.startswith("HIGH:"):
                continue   # Solo los HIGH van al informe de cliente
            n += 1
            hallazgos.append(VSLFinding(
                id          = f"SDT-{n:03d}",
                title       = f"NS Takeover potencial — {r.subdomain}"[:80],
                severity    = "HIGH",
                description = (
                    f"El subdominio '{r.subdomain}' tiene un registro NS que apunta a un nameserver "
                    "cuyo dominio no está registrado. Un atacante podría registrar ese dominio y "
                    "tomar el control del servicio de nombres del subdominio."
                ),
                evidence    = (
                    f"Subdominio: {r.subdomain}\n"
                    f"Hallazgo NS: {issue}\n"
                    f"Fuente: DNS pasivo (no se envió tráfico al objetivo)"
                ),
                affected    = r.subdomain,
                remediation = (
                    f"Eliminar el registro NS de '{r.subdomain}' si el nameserver ya no existe, "
                    "o actualizar el NS a un nameserver válido y controlado por la organización."
                ),
                tags        = ["dns", "ns-takeover", "subdomain"],
            ))

    # ── Hallazgos MX takeover (v1.1) ──
    for r in results:
        if not r.mx_issues:
            continue
        for issue in r.mx_issues:
            sev = "HIGH" if issue.startswith("HIGH:") else "MEDIUM"
            n += 1
            if issue.startswith("HIGH:"):
                titulo   = f"MX Takeover potencial — {r.subdomain}"[:80]
                desc     = (
                    f"El subdominio '{r.subdomain}' tiene un registro MX que apunta a un servidor "
                    "de correo cuyo dominio no está registrado. Un atacante podría registrar ese "
                    "dominio e interceptar correos dirigidos a este subdominio."
                )
                remedio  = (
                    f"Eliminar o actualizar el registro MX de '{r.subdomain}' para apuntar a "
                    "un servidor de correo válido y controlado por la organización."
                )
            else:
                titulo   = f"MX apunta a proveedor SaaS — verificar ownership — {r.subdomain}"[:80]
                desc     = (
                    f"El subdominio '{r.subdomain}' tiene un registro MX apuntando a un proveedor "
                    "SaaS de correo que permite reclamar dominios. Si la cuenta en ese proveedor "
                    "ya no está activa, un atacante podría reclamarla."
                )
                remedio  = (
                    f"Verificar que la cuenta del proveedor SaaS asociada a '{r.subdomain}' sigue "
                    "activa y es propiedad de la organización. Si no se usa, eliminar el registro MX."
                )

            hallazgos.append(VSLFinding(
                id          = f"SDT-{n:03d}",
                title       = titulo,
                severity    = sev,
                description = desc,
                evidence    = (
                    f"Subdominio: {r.subdomain}\n"
                    f"Hallazgo MX: {issue}\n"
                    f"Fuente: DNS pasivo"
                ),
                affected    = r.subdomain,
                remediation = remedio,
                tags        = ["dns", "mx-takeover", "email", "subdomain"],
            ))

    return hallazgos


# ─────────────────────────────────────────────────────────────────────────────
# Punto de entrada
# ─────────────────────────────────────────────────────────────────────────────

async def main() -> None:
    console.print(BANNER, style="bold magenta")

    args = _parse_args()

    console.print(f"  Objetivo: [cyan]{args.domain}[/]  ·  "
                  f"Concurrencia: [yellow]{args.concurrency}[/]  ·  "
                  f"Timeout HTTP: [yellow]{args.http_timeout}s[/]\n")

    # ── Modo monitor continuo ─────────────────────────────────────────────────
    if args.monitor > 0:
        await run_monitor_mode(args.domain, args.monitor, args)
        return

    # ── Construir lista de subdominios ────────────────────────────────────────

    subdomains: Set[str] = set()

    if args.subdomains:
        subdomains = {s.strip() for s in args.subdomains.split(",") if s.strip()}
        console.print(f"[dim]  Subdominios directos: {len(subdomains)}[/]")

    if args.from_file:
        loaded = _load_from_file(args.from_file)
        subdomains.update(loaded)
        console.print(f"[dim]  Cargados desde fichero: {len(loaded)}[/]")

    if not subdomains:
        console.print("[bold cyan]  FASE 1[/] — Enumerando subdominios via OSINT (6 fuentes)...")
        enumerator = SubdomainEnumerator(args.domain)
        subdomains = await enumerator.enumerate()
        console.print(f"[dim]  Subdominios encontrados: {len(subdomains)}[/]")

    if not subdomains:
        console.print("[yellow]  No se encontraron subdominios. Verifica el dominio e inténtalo de nuevo.[/]")
        return

    console.print(f"\n[bold cyan]  FASE 2+3[/] — Resolviendo CNAME y verificando takeover "
                  f"([cyan]{len(subdomains)}[/] subdominios)...\n")

    # ── Escaneo ───────────────────────────────────────────────────────────────

    scanner = TakeoverScanner(
        concurrency=args.concurrency,
        http_timeout=args.http_timeout,
        verify=not args.no_verify,
    )

    with console.status("[bold green]Escaneando...[/]", spinner="dots"):
        results: List[SubdomainResult] = await scanner.scan(subdomains)

    # ── Tabla de resultados ───────────────────────────────────────────────────

    if args.only_vulnerable:
        display = [r for r in results if r.status in (TakeoverStatus.VULNERABLE, TakeoverStatus.POTENTIAL)]
    else:
        display = results

    console.print(_build_results_table(display))
    _print_vuln_panels(results)

    # ── Resumen ───────────────────────────────────────────────────────────────

    n_vuln = sum(1 for r in results if r.status == TakeoverStatus.VULNERABLE)
    n_pot  = sum(1 for r in results if r.status == TakeoverStatus.POTENTIAL)
    summary_style = "bold red" if n_vuln > 0 else ("bold yellow" if n_pot > 0 else "bold green")
    console.print(
        f"\n[{summary_style}]  RESUMEN: {len(results)} subdominios · "
        f"{n_vuln} VULNERABLE · {n_pot} POTENTIAL[/]"
    )

    # ── Exportación ───────────────────────────────────────────────────────────

    if args.output:
        _export_json(results, args.output)
    if args.html:
        _export_html(results, args.domain, args.html)

    # ── Informe unificado VSL (cliente) ───────────────────────────────────────
    if getattr(args, "report_html", None) or getattr(args, "report_pdf", None):
        from vampsec_report import VampSecReport, meta_from_args
        meta   = meta_from_args(args, tool="vamp-subdomain-takeover", version=VERSION)
        report = VampSecReport(meta=meta, findings=_findings_vsl(results, args.domain))
        if args.report_html:
            report.to_html_client(args.report_html)
            console.print(f"  [bold green]✔ Informe cliente HTML guardado: {args.report_html}[/]")
        if args.report_pdf:
            report.to_pdf(args.report_pdf)
            console.print(f"  [bold green]✔ Informe cliente PDF guardado: {args.report_pdf}[/]")

    if n_vuln > 0:
        sys.exit(2)   # exit code 2 = hallazgos críticos (útil en CI/CD)
    elif n_pot > 0:
        sys.exit(1)   # exit code 1 = hallazgos potenciales


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[dim]  Escaneo interrumpido por el usuario.[/]")
        sys.exit(130)
