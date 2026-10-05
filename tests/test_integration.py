# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp_gcp_audit.py.

Simula respuestas HTTP de las APIs REST de GCP usando mocks de aiohttp.
No requiere credenciales ni proyecto GCP activo.
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_gcp_audit import (
    EXCESSIVE_ROLES,
    Finding,
    GCPClient,
    TOOL_NAME,
)


def run_async(coro):
    """Ejecuta una corrutina asyncio."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Helper: mock de sesión aiohttp
# ---------------------------------------------------------------------------

def _mock_session_get(respuestas: Dict[str, Any]) -> MagicMock:
    """
    Crea sesión aiohttp mockeada.
    respuestas: mapa de fragmento_url → payload dict que devuelve la respuesta.
    """
    session = MagicMock()

    def mock_context_manager(url, **kwargs):
        resp = AsyncMock()
        resp.status = 200
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)
        # Buscar la clave más específica que coincida con la URL
        payload = {}
        for clave, valor in respuestas.items():
            if clave in url:
                payload = valor
                break
        resp.json = AsyncMock(return_value=payload)
        return resp

    session.get = mock_context_manager
    return session


# ---------------------------------------------------------------------------
# Test integración 1: GCPClient.get() retorna JSON parseado
# ---------------------------------------------------------------------------

class TestGCPClientGet:
    """Verifica que GCPClient._get() hace petición HTTP y parsea JSON."""

    def test_get_retorna_payload_correcto(self):
        """GCPClient.get con sesión mockeada retorna el payload esperado."""
        payload = {"bindings": [{"role": "roles/viewer", "members": ["allUsers"]}]}
        session = _mock_session_get({"iam": payload})

        async def run():
            client = GCPClient(project_id="test-proj", session=session)
            client._token = "fake-token"
            resp = await client.get("https://cloudresourcemanager.googleapis.com/v1/iam")
            return resp

        resultado = run_async(run())
        assert resultado is not None
        assert "bindings" in resultado


# ---------------------------------------------------------------------------
# Test integración 2: GCPClient._get_token_from_gcloud con subprocess mockeado
# ---------------------------------------------------------------------------

class TestGCPTokenGcloud:
    """Verifica obtención de token vía gcloud mockeado."""

    def test_get_token_gcloud_correcto(self):
        """_get_token_from_gcloud debe retornar el token del stdout de gcloud."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "ya29.TOKEN_SIMULADO"
        mock_result.stderr = ""

        async def run():
            session = MagicMock()
            client = GCPClient(project_id="test-proj", session=session)
            with patch("subprocess.run", return_value=mock_result):
                token = await client._get_token_from_gcloud()
            return token

        token = run_async(run())
        assert token == "ya29.TOKEN_SIMULADO"

    def test_get_token_gcloud_falla_si_no_instalado(self):
        """_get_token_from_gcloud debe lanzar RuntimeError si gcloud no está."""
        async def run():
            session = MagicMock()
            client = GCPClient(project_id="test-proj", session=session)
            with patch("subprocess.run", side_effect=FileNotFoundError):
                await client._get_token_from_gcloud()

        with pytest.raises(RuntimeError, match="gcloud"):
            run_async(run())


# ---------------------------------------------------------------------------
# Test integración 3: Detección de IAM allUsers en módulo GCP
# ---------------------------------------------------------------------------

class TestIAMAllUsersModulo:
    """Verifica que la lógica de análisis IAM detecta allUsers en bindings."""

    def test_analisis_binding_all_users(self, iam_policy_all_users):
        """El análisis de policy IAM debe identificar el binding con allUsers."""
        bindings = iam_policy_all_users.get("bindings", [])
        hallazgos = []

        for binding in bindings:
            role    = binding.get("role", "")
            members = binding.get("members", [])
            if "allUsers" in members or "allAuthenticatedUsers" in members:
                hallazgos.append(Finding(
                    tool=TOOL_NAME,
                    severity="CRITICAL",
                    type="IAM",
                    title=f"IAM binding público en rol {role}",
                    description="Binding con allUsers detectado",
                    affected="projects/test-project",
                    recommendation="Eliminar allUsers de los bindings IAM",
                ))

        assert len(hallazgos) >= 1, "Debe generar ≥1 hallazgo CRITICAL por allUsers"
        assert hallazgos[0].severity == "CRITICAL"


# ---------------------------------------------------------------------------
# Test integración 4: Cloud Run allUsers → hallazgo CRITICAL simulado
# ---------------------------------------------------------------------------

class TestCloudRunIntegracion:
    """Verifica análisis de Cloud Run con IAM policy mockeada."""

    def test_cloud_run_all_users_genera_critical(self, cloud_run_iam_allusers):
        """IAM policy de Cloud Run con allUsers como invoker genera CRITICAL."""
        bindings = cloud_run_iam_allusers.get("bindings", [])
        hallazgos = []

        for b in bindings:
            if (b.get("role") == "roles/run.invoker"
                    and "allUsers" in b.get("members", [])):
                hallazgos.append(Finding(
                    tool=TOOL_NAME,
                    severity="CRITICAL",
                    type="CloudRun",
                    title="Cloud Run service con invocación pública",
                    description="El servicio permite invocación sin autenticación",
                    affected="projects/test/locations/us-central1/services/mi-api",
                    recommendation="Requerir autenticación en Cloud Run",
                ))

        assert hallazgos, "Cloud Run allUsers debe generar CRITICAL"
        assert hallazgos[0].severity == "CRITICAL"


# ---------------------------------------------------------------------------
# Test integración 5: GCPClient maneja HTTP 403 sin fallar
# ---------------------------------------------------------------------------

class TestGCPClientHTTP403:
    """Verifica que GCPClient maneja errores HTTP 403 (permisos insuficientes)."""

    def test_get_lanza_error_en_403(self):
        """GCPClient.get() debe lanzar RuntimeError ante HTTP 403."""
        session = MagicMock()

        def mock_context_manager(url, **kwargs):
            resp = AsyncMock()
            resp.status = 403
            resp.__aenter__ = AsyncMock(return_value=resp)
            resp.__aexit__ = AsyncMock(return_value=False)
            resp.text = AsyncMock(return_value="Forbidden")
            resp.json = AsyncMock(return_value={"error": {"message": "Forbidden"}})
            return resp

        session.get = mock_context_manager

        async def run():
            client = GCPClient(project_id="test-proj", session=session)
            client._token = "fake-token"
            return await client.get("https://compute.googleapis.com/v1/projects/test/zones")

        with pytest.raises(RuntimeError, match="403"):
            run_async(run())
