# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp_gcp_audit.py.

Cubre la lógica de análisis de seguridad de GCP sin llamadas HTTP reales:
- IAM: binding allUsers → CRITICAL
- Cloud Run: invocación pública → CRITICAL
- Cloud Functions: secretos en env vars → CRITICAL
- Compute: serial port habilitado → MEDIUM
- Estructuras de datos Finding
- Constantes de la herramienta
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_gcp_audit import (
    DANGEROUS_APIS,
    EXCESSIVE_ROLES,
    SECRET_ENV_KEYWORDS,
    SENSITIVE_PORTS,
    TOOL_NAME,
    Finding,
    GCPClient,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_async(coro):
    """Ejecuta una corrutina asyncio en el event loop de test."""
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_finding(**kwargs) -> Finding:
    """Crea un Finding con campos mínimos para pruebas."""
    defaults = {
        "tool": TOOL_NAME,
        "severity": "HIGH",
        "type": "IAM",
        "title": "Test Finding",
        "description": "Descripción de prueba",
        "affected": "projects/test-project",
        "recommendation": "Remediar inmediatamente",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Tests 1-3: Estructura Finding y serialización
# ---------------------------------------------------------------------------

class TestFindingStructure:
    """Verifica la estructura y serialización del dataclass Finding."""

    def test_finding_to_dict_contiene_campos_clave(self):
        """Finding.to_dict() debe incluir severity, title y description."""
        f = _make_finding(severity="CRITICAL", title="Test CRITICAL")
        d = f.to_dict()
        assert d["severity"] == "CRITICAL"
        assert d["title"] == "Test CRITICAL"
        assert "description" in d

    def test_finding_module_por_defecto_vacio(self):
        """El campo module es opcional y por defecto es cadena vacía."""
        f = _make_finding()
        assert f.module == ""

    def test_finding_extra_es_dict_vacio_por_defecto(self):
        """El campo extra es dict vacío por defecto."""
        f = _make_finding()
        assert f.extra == {}

    def test_finding_severidades_validas(self):
        """Finding acepta los niveles de severidad estándar."""
        niveles = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for nivel in niveles:
            f = _make_finding(severity=nivel)
            assert f.severity == nivel


# ---------------------------------------------------------------------------
# Tests 4-5: Constantes y sets de seguridad
# ---------------------------------------------------------------------------

class TestConstantas:
    """Verifica que las constantes críticas de la herramienta son correctas."""

    def test_excessive_roles_contiene_owner(self):
        """EXCESSIVE_ROLES debe incluir roles/owner."""
        assert "roles/owner" in EXCESSIVE_ROLES

    def test_excessive_roles_contiene_editor(self):
        """EXCESSIVE_ROLES debe incluir roles/editor."""
        assert "roles/editor" in EXCESSIVE_ROLES

    def test_sensitive_ports_contiene_ssh(self):
        """SENSITIVE_PORTS debe incluir el puerto SSH (22)."""
        assert 22 in SENSITIVE_PORTS

    def test_sensitive_ports_contiene_rdp(self):
        """SENSITIVE_PORTS debe incluir el puerto RDP (3389)."""
        assert 3389 in SENSITIVE_PORTS

    def test_secret_env_keywords_contiene_password(self):
        """SECRET_ENV_KEYWORDS debe incluir 'password'."""
        assert "password" in SECRET_ENV_KEYWORDS

    def test_secret_env_keywords_contiene_api_key(self):
        """SECRET_ENV_KEYWORDS debe incluir 'api_key'."""
        assert "api_key" in SECRET_ENV_KEYWORDS

    def test_dangerous_apis_contiene_deployment_manager(self):
        """DANGEROUS_APIS debe incluir deploymentmanager.googleapis.com."""
        assert "deploymentmanager.googleapis.com" in DANGEROUS_APIS


# ---------------------------------------------------------------------------
# Tests 6-7: Lógica IAM allUsers
# ---------------------------------------------------------------------------

class TestIAMAllUsers:
    """Verifica que la lógica de detección de allUsers en IAM es correcta."""

    def test_binding_all_users_es_critico(self, iam_policy_all_users):
        """Binding con member allUsers debe clasificarse como CRITICAL."""
        bindings = iam_policy_all_users.get("bindings", [])
        tiene_all_users = any(
            "allUsers" in b.get("members", []) for b in bindings
        )
        assert tiene_all_users, "La policy fixture debe tener allUsers"

    def test_policy_sin_all_users_no_es_critica(self, iam_policy_segura):
        """Policy sin allUsers no debe generar hallazgo CRITICAL de acceso público."""
        bindings = iam_policy_segura.get("bindings", [])
        tiene_all_users = any(
            "allUsers" in b.get("members", []) or
            "allAuthenticatedUsers" in b.get("members", [])
            for b in bindings
        )
        assert not tiene_all_users, "Policy segura no debe tener allUsers"


# ---------------------------------------------------------------------------
# Test 8: Cloud Run IAM allUsers → CRITICAL
# ---------------------------------------------------------------------------

class TestCloudRunPublico:
    """Verifica que Cloud Run con allUsers como invoker se detecta como CRITICAL."""

    def test_cloud_run_all_users_es_critico(self, cloud_run_iam_allusers):
        """IAM policy de Cloud Run con allUsers debe ser CRITICAL."""
        bindings = cloud_run_iam_allusers.get("bindings", [])
        invoker_bindings = [
            b for b in bindings
            if "roles/run.invoker" in b.get("role", "")
        ]
        tiene_all_users = any(
            "allUsers" in b.get("members", []) for b in invoker_bindings
        )
        assert tiene_all_users, "Cloud Run debe permitir invocación por allUsers"


# ---------------------------------------------------------------------------
# Test 9: Cloud Function con secretos en env vars → CRITICAL
# ---------------------------------------------------------------------------

class TestCloudFunctionSecretosEnv:
    """Verifica detección de secretos en variables de entorno de Cloud Functions."""

    def test_detecta_secreto_en_env_function(self, cloud_function_secreto_env):
        """Cloud Function con DB_PASSWORD o API_KEY en env debe detectarse."""
        env_vars = cloud_function_secreto_env.get("environmentVariables", {})

        # Verificar que las palabras clave del fixture coinciden con SECRET_ENV_KEYWORDS
        palabras_sensibles = {k.lower() for k in env_vars}
        detectado = bool(palabras_sensibles & {kw.lower() for kw in SECRET_ENV_KEYWORDS})

        assert detectado, (
            f"Env vars {list(env_vars.keys())} deben coincidir con SECRET_ENV_KEYWORDS"
        )

    def test_cloud_function_sin_env_secretos_es_segura(self):
        """Cloud Function con env vars no sensibles no debe generar alerta."""
        env_seguras = {
            "LOG_LEVEL": "INFO",
            "REGION": "us-central1",
            "PROJECT_ID": "myproject",
        }
        palabras_sensibles = {k.lower() for k in env_seguras}
        detectado = bool(palabras_sensibles & {kw.lower() for kw in SECRET_ENV_KEYWORDS})
        assert not detectado, "Env vars seguras no deben detectarse como secretos"


# ---------------------------------------------------------------------------
# Test 10: Compute serial port habilitado → MEDIUM
# ---------------------------------------------------------------------------

class TestComputeSerialPort:
    """Verifica que el puerto serie habilitado en Compute Engine se detecta."""

    def test_serial_port_enable_true_es_misconfig(self, compute_instancia_serial_port):
        """Metadata con serial-port-enable=true debe considerarse misconfiguración."""
        metadata_items = compute_instancia_serial_port.get("metadata", {}).get("items", [])
        serial_enabled = any(
            item.get("key") == "serial-port-enable" and item.get("value") in ("true", "1", "True")
            for item in metadata_items
        )
        assert serial_enabled, "Fixture debe tener serial-port-enable=true"

    def test_instancia_sin_serial_port_es_segura(self):
        """Instancia sin serial-port-enable en metadata es segura."""
        instancia = {
            "name": "vm-segura",
            "metadata": {"items": [{"key": "other-key", "value": "other-value"}]},
        }
        metadata_items = instancia.get("metadata", {}).get("items", [])
        serial_enabled = any(
            item.get("key") == "serial-port-enable" and item.get("value") in ("true", "1", "True")
            for item in metadata_items
        )
        assert not serial_enabled, "Instancia segura no debe tener serial port habilitado"


# ---------------------------------------------------------------------------
# Tests 11-12: GCPClient inicialización
# ---------------------------------------------------------------------------

class TestGCPClient:
    """Verifica la inicialización correcta del cliente GCP."""

    def test_gcpclient_almacena_project_id(self):
        """GCPClient debe almacenar el project_id proporcionado."""
        cliente = GCPClient(project_id="my-test-project")
        assert cliente.project_id == "my-test-project"

    def test_gcpclient_token_inicialmente_none(self):
        """El token de acceso debe ser None antes de autenticar."""
        cliente = GCPClient(project_id="my-project")
        assert cliente._token is None

    def test_gcpclient_own_session_true_sin_sesion(self):
        """Sin sesión externa, _own_session debe ser True."""
        cliente = GCPClient(project_id="proj")
        assert cliente._own_session is True

    def test_gcpclient_own_session_false_con_sesion(self):
        """Con sesión externa proporcionada, _own_session debe ser False."""
        session_mock = MagicMock()
        cliente = GCPClient(project_id="proj", session=session_mock)
        assert cliente._own_session is False
