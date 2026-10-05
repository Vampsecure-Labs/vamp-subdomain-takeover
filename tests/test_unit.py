# © VampSecure Studios — VampSecure Labs Security Research Division
"""Tests unitarios para vamp-subdomain-takeover."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Parchear dnspython y aiohttp antes de importar
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


# ── Tests para SERVICE_SIGNATURES ────────────────────────────────────────────

class TestServiceSignatures:
    """Pruebas para la base de datos de firmas de servicios."""

    def test_github_pages_presente(self):
        """GitHub Pages debe estar en la base de datos de firmas."""
        assert "github.io" in vst.SERVICE_SIGNATURES

    def test_s3_tiene_fingerprint_nosuchbucket(self):
        """AWS S3 debe tener como fingerprint 'NoSuchBucket'."""
        assert "NoSuchBucket" in vst.SERVICE_SIGNATURES["s3.amazonaws.com"]["fingerprint"]

    def test_heroku_tiene_fingerprint_correcto(self):
        """Heroku debe tener como fingerprint 'No such app'."""
        assert "No such app" in vst.SERVICE_SIGNATURES["herokuapp.com"]["fingerprint"]

    def test_netlify_tiene_cvss_alto(self):
        """Netlify debe tener un CVSS mayor o igual a 8.0."""
        cvss = float(vst.SERVICE_SIGNATURES["netlify.app"]["cvss"])
        assert cvss >= 8.0

    def test_github_pages_tiene_cvss_critico(self):
        """GitHub Pages debe tener CVSS >= 9.0 (takeover muy peligroso)."""
        cvss = float(vst.SERVICE_SIGNATURES["github.io"]["cvss"])
        assert cvss >= 9.0

    def test_todos_tienen_campos_obligatorios(self):
        """Todas las entradas deben tener 'name', 'fingerprint' y 'cvss'."""
        for key, sig in vst.SERVICE_SIGNATURES.items():
            assert "name" in sig, f"Firma '{key}' falta campo 'name'"
            assert "fingerprint" in sig, f"Firma '{key}' falta campo 'fingerprint'"
            assert "cvss" in sig, f"Firma '{key}' falta campo 'cvss'"

    def test_cvss_es_numero_valido(self):
        """El CVSS de todas las firmas debe ser convertible a float."""
        for key, sig in vst.SERVICE_SIGNATURES.items():
            try:
                v = float(sig["cvss"])
                assert 0.0 <= v <= 10.0, f"CVSS fuera de rango en '{key}': {v}"
            except (ValueError, TypeError):
                pytest.fail(f"CVSS inválido en '{key}': {sig['cvss']}")


# ── Tests para TakeoverStatus ─────────────────────────────────────────────────

class TestTakeoverStatus:
    """Pruebas para el enum de estados de takeover."""

    def test_vulnerable_es_string_correcto(self):
        """TakeoverStatus.VULNERABLE debe valer 'VULNERABLE'."""
        assert vst.TakeoverStatus.VULNERABLE == "VULNERABLE"

    def test_potential_es_string_correcto(self):
        """TakeoverStatus.POTENTIAL debe valer 'POTENTIAL'."""
        assert vst.TakeoverStatus.POTENTIAL == "POTENTIAL"

    def test_safe_es_string_correcto(self):
        """TakeoverStatus.SAFE debe valer 'SAFE'."""
        assert vst.TakeoverStatus.SAFE == "SAFE"


# ── Tests para SubdomainResult ────────────────────────────────────────────────

class TestSubdomainResult:
    """Pruebas para el modelo de datos SubdomainResult."""

    def test_resultado_default_es_safe(self):
        """Un resultado recién creado debe tener estado SAFE por defecto."""
        resultado = vst.SubdomainResult(subdomain="test.ejemplo.com")
        assert resultado.status == vst.TakeoverStatus.SAFE
        assert resultado.fingerprint_found is False
        assert resultado.cname_chain == []

    def test_to_dict_serializa_status_como_string(self):
        """to_dict() debe serializar el enum status como string."""
        resultado = vst.SubdomainResult(
            subdomain="test.ejemplo.com",
            status=vst.TakeoverStatus.VULNERABLE,
        )
        d = resultado.to_dict()
        assert d["status"] == "VULNERABLE"
        assert isinstance(d["status"], str)

    def test_resultado_vulnerable_tiene_fingerprint(self, resultado_vulnerable):
        """Un resultado VULNERABLE debe tener fingerprint_found=True."""
        assert resultado_vulnerable.fingerprint_found is True
        assert resultado_vulnerable.status == vst.TakeoverStatus.VULNERABLE

    def test_resultado_safe_no_tiene_servicio(self, resultado_safe):
        """Un resultado SAFE no debe tener servicio asignado."""
        assert resultado_safe.service is None
        assert resultado_safe.cvss is None


# ── Tests para TakeoverScanner._match_service ─────────────────────────────────

class TestTakeoverScannerMatchService:
    """Pruebas para la detección de servicios por cadena CNAME."""

    def test_github_io_detectado_en_cname(self):
        """Una cadena CNAME con 'github.io' debe detectar GitHub Pages."""
        scanner = vst.TakeoverScanner()
        resultado = scanner._match_service(["empresa.github.io"])
        assert resultado is not None
        key, name = resultado
        assert key == "github.io"
        assert "GitHub" in name

    def test_heroku_detectado_en_cname(self):
        """Una cadena CNAME con 'herokuapp.com' debe detectar Heroku."""
        scanner = vst.TakeoverScanner()
        resultado = scanner._match_service(["mi-app.herokuapp.com"])
        assert resultado is not None
        key, name = resultado
        assert key == "herokuapp.com"

    def test_s3_detectado_en_cname(self):
        """Una cadena CNAME con 's3.amazonaws.com' debe detectar AWS S3."""
        scanner = vst.TakeoverScanner()
        resultado = scanner._match_service(["mi-bucket.s3.amazonaws.com"])
        assert resultado is not None
        assert resultado[0] == "s3.amazonaws.com"

    def test_cname_propio_no_detecta_servicio(self):
        """Una cadena CNAME interna no debe detectar ningún servicio externo."""
        scanner = vst.TakeoverScanner()
        resultado = scanner._match_service(["www.empresa-auditada.com", "servers.empresa.es"])
        assert resultado is None

    def test_cadena_vacia_devuelve_none(self):
        """Una cadena CNAME vacía debe devolver None."""
        scanner = vst.TakeoverScanner()
        resultado = scanner._match_service([])
        assert resultado is None


# ── Tests para TakeoverScanner._verify_http ───────────────────────────────────

class TestTakeoverScannerVerifyHttp:
    """Pruebas para la verificación HTTP de fingerprints."""

    @pytest.mark.asyncio
    async def test_fingerprint_encontrado_devuelve_true(self,
                                                         respuesta_github_pages_no_reclamada):
        """Si el body contiene el fingerprint, debe devolver fingerprint_found=True."""
        scanner = vst.TakeoverScanner()

        mock_resp = AsyncMock()
        mock_resp.status = 404
        mock_resp.text = AsyncMock(return_value=respuesta_github_pages_no_reclamada)

        mock_get = MagicMock()
        mock_get.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_get.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_get)

        http_status, found = await scanner._verify_http(
            "old.empresa.com", "github.io", mock_session
        )
        assert found is True

    @pytest.mark.asyncio
    async def test_fingerprint_no_encontrado_devuelve_false(self,
                                                              respuesta_netlify_activa):
        """Si el body no contiene el fingerprint, debe devolver fingerprint_found=False."""
        scanner = vst.TakeoverScanner()

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=respuesta_netlify_activa)

        mock_get = MagicMock()
        mock_get.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_get.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_get)

        http_status, found = await scanner._verify_http(
            "docs.empresa.com", "netlify.app", mock_session
        )
        assert found is False
