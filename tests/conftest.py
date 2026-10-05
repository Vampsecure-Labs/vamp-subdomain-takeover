# © VampSecure Studios — VampSecure Labs Security Research Division
"""Fixtures compartidas para los tests de vamp-subdomain-takeover."""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def dominio_objetivo():
    """Dominio raíz para los tests de subdomain takeover."""
    return "empresa-auditada.com"


@pytest.fixture
def subdominios_con_cname():
    """Lista de subdominios con cadenas CNAME conocidas."""
    return {
        "old.empresa-auditada.com":       ["old.empresa-auditada.com.github.io"],
        "api.empresa-auditada.com":       ["api-empresa-auditada.herokuapp.com"],
        "docs.empresa-auditada.com":      ["empresa-docs.netlify.app"],
        "cdn.empresa-auditada.com":       ["empresa-cdn.s3.amazonaws.com"],
        "status.empresa-auditada.com":    ["active.empresa-auditada.com"],  # CNAME interno
        "shop.empresa-auditada.com":      ["empresa.myshopify.com"],
    }


@pytest.fixture
def respuesta_github_pages_no_reclamada():
    """Respuesta HTTP simulada de GitHub Pages para endpoint no reclamado."""
    return "There isn't a GitHub Pages site here."


@pytest.fixture
def respuesta_heroku_no_reclamada():
    """Respuesta HTTP simulada de Heroku para endpoint no reclamado."""
    return "No such app"


@pytest.fixture
def respuesta_s3_no_reclamada():
    """Respuesta HTTP simulada de S3 para bucket no existente."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchBucket</Code>
  <Message>The specified bucket does not exist</Message>
</Error>"""


@pytest.fixture
def respuesta_netlify_activa():
    """Respuesta HTTP simulada de Netlify para sitio activo (sin takeover)."""
    return "<html><head><title>Mi Sitio</title></head><body><h1>Bienvenido</h1></body></html>"


@pytest.fixture
def resultado_vulnerable():
    """SubdomainResult de ejemplo para un subdominio vulnerable."""
    from vamp_subdomain_takeover import SubdomainResult, TakeoverStatus
    return SubdomainResult(
        subdomain="old.empresa-auditada.com",
        cname_chain=["old.empresa-auditada.com.github.io"],
        service="GitHub Pages",
        service_key="github.io",
        cvss="9.0",
        status=TakeoverStatus.VULNERABLE,
        http_status=404,
        fingerprint_found=True,
    )


@pytest.fixture
def resultado_safe():
    """SubdomainResult de ejemplo para un subdominio seguro."""
    from vamp_subdomain_takeover import SubdomainResult, TakeoverStatus
    return SubdomainResult(
        subdomain="www.empresa-auditada.com",
        cname_chain=[],
        service=None,
        service_key=None,
        cvss=None,
        status=TakeoverStatus.SAFE,
        http_status=200,
        fingerprint_found=False,
    )
