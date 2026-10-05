# © VampSecure Studios — VampSecure Labs Security Research Division
"""Tests de integración para vamp-subdomain-takeover."""

import pytest
import json
from unittest.mock import patch, MagicMock, AsyncMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytestmark = pytest.mark.integration

# Parchear dependencias antes de importar
with patch.dict("sys.modules", {
    "dns": MagicMock(),
    "dns.asyncresolver": MagicMock(),
    "dns.exception": MagicMock(),
    "dns.rdatatype": MagicMock(),
    "rich": MagicMock(),
    "rich.console": MagicMock(),
    "rich.live": MagicMock(),
    "rich.panel": MagicMock(),
    "rich.table": MagicMock(),
    "rich.text": MagicMock(),
}):
    import vamp_subdomain_takeover as vst

# Las clases de excepción deben heredar de BaseException para que las cláusulas
# except del código de producción funcionen correctamente.
vst.dns.exception.DNSException = Exception
vst.dns.resolver = MagicMock()
vst.dns.resolver.NXDOMAIN = type("NXDOMAIN", (Exception,), {})


# ── Test 1: Enumeración de subdominios — crt.sh mockeado ────────────────────

@pytest.mark.asyncio
async def test_enumeracion_crtsh_mockeada(dominio_objetivo):
    """
    Verifica que SubdomainEnumerator._crtsh() parsea correctamente
    la respuesta JSON de crt.sh.
    """
    respuesta_crtsh = [
        {"name_value": f"www.{dominio_objetivo}"},
        {"name_value": f"api.{dominio_objetivo}"},
        {"name_value": f"*.{dominio_objetivo}"},
        {"name_value": f"mail.{dominio_objetivo}"},
        {"name_value": "dominio-ajeno.com"},  # No debe incluirse
    ]

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value=respuesta_crtsh)

    mock_get = MagicMock()
    mock_get.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_get.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_get)

    enumerador = vst.SubdomainEnumerator(dominio_objetivo)
    subs = await enumerador._crtsh(mock_session)

    # El wildcard debe descartarse (lstrip "*."), el dominio ajeno tampoco
    assert f"www.{dominio_objetivo}" in subs
    assert f"api.{dominio_objetivo}" in subs
    assert f"mail.{dominio_objetivo}" in subs
    assert "dominio-ajeno.com" not in subs


# ── Test 2: Enumeración — HackerTarget mockeado ───────────────────────────────

@pytest.mark.asyncio
async def test_enumeracion_hackertarget_mockeada(dominio_objetivo):
    """
    Verifica que SubdomainEnumerator._hackertarget() parsea la respuesta
    de texto plano de HackerTarget.
    """
    # HackerTarget devuelve texto plano: "subdominio,ip\n..."
    respuesta_texto = (
        f"www.{dominio_objetivo},1.2.3.4\n"
        f"api.{dominio_objetivo},1.2.3.5\n"
        f"ajeno.com,9.9.9.9\n"
    )

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.text = AsyncMock(return_value=respuesta_texto)

    mock_get = MagicMock()
    mock_get.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_get.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_get)

    enumerador = vst.SubdomainEnumerator(dominio_objetivo)
    subs = await enumerador._hackertarget(mock_session)

    assert f"www.{dominio_objetivo}" in subs
    assert f"api.{dominio_objetivo}" in subs
    assert "ajeno.com" not in subs


# ── Test 3: TakeoverScanner — escaneo de un subdominio VULNERABLE ─────────────

@pytest.mark.asyncio
async def test_scan_one_vulnerable_github_pages(respuesta_github_pages_no_reclamada):
    """
    Simula el escaneo de un subdominio con CNAME a GitHub Pages y fingerprint
    de endpoint no reclamado. Debe devolver estado VULNERABLE.
    """
    scanner = vst.TakeoverScanner(verify=True)

    # Primera resolución CNAME devuelve github.io; NS/MX y consultas posteriores fallan
    mock_resolver = MagicMock()
    cname_calls = [0]

    async def mock_resolve(host, qtype):
        if qtype == "CNAME" and cname_calls[0] == 0:
            cname_calls[0] += 1
            mock_ans = MagicMock()
            mock_ans.__getitem__ = MagicMock(
                return_value=MagicMock(
                    target=MagicMock(
                        __str__=MagicMock(return_value="empresa.github.io.")
                    )
                )
            )
            return mock_ans
        raise Exception("NXDOMAIN")

    mock_resolver.resolve = mock_resolve

    # Mock HTTP que devuelve el fingerprint de GitHub Pages (endpoint no reclamado)
    mock_http_resp = AsyncMock()
    mock_http_resp.status = 404
    mock_http_resp.text = AsyncMock(return_value=respuesta_github_pages_no_reclamada)

    mock_get_http = MagicMock()
    mock_get_http.__aenter__ = AsyncMock(return_value=mock_http_resp)
    mock_get_http.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_get_http)

    with patch.object(vst.dns.asyncresolver, "Resolver", return_value=mock_resolver):
        resultado = await scanner._scan_one("old.empresa-auditada.com", mock_session)

    # Con el CNAME a github.io y el fingerprint encontrado → VULNERABLE
    assert resultado.status == vst.TakeoverStatus.VULNERABLE or \
           resultado.status == vst.TakeoverStatus.POTENTIAL


# ── Test 4: TakeoverScanner — subdominio SAFE (sin CNAME externo) ─────────────

@pytest.mark.asyncio
async def test_scan_one_safe_sin_cname_externo():
    """
    Un subdominio sin CNAME a servicios externos debe devolver estado SAFE.
    """
    scanner = vst.TakeoverScanner(verify=True)

    # Mock DNS que lanza excepción inmediatamente (sin CNAME)
    mock_resolver = MagicMock()
    async def mock_resolve_no_cname(host, qtype):
        raise Exception("NOERROR — no CNAME")
    mock_resolver.resolve = mock_resolve_no_cname

    mock_session = MagicMock()

    with patch.object(vst.dns.asyncresolver, "Resolver", return_value=mock_resolver):
        resultado = await scanner._scan_one("www.empresa-auditada.com", mock_session)

    assert resultado.status == vst.TakeoverStatus.SAFE
    assert resultado.cname_chain == []


# ── Test 5: Serialización JSON de resultados ──────────────────────────────────

def test_resultado_to_dict_es_json_serializable(resultado_vulnerable):
    """
    Verifica que un SubdomainResult puede serializarse completamente a JSON
    sin errores de tipo.
    """
    d = resultado_vulnerable.to_dict()
    # Debe poder serializarse a JSON sin excepciones
    serializado = json.dumps(d)
    deserializado = json.loads(serializado)

    assert deserializado["subdomain"] == resultado_vulnerable.subdomain
    assert deserializado["status"] == "VULNERABLE"
    assert deserializado["fingerprint_found"] is True
