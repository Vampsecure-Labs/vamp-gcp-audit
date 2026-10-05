# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidas para la suite de test de vamp-gcp-audit.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Fixtures de respuestas API GCP simuladas
# ---------------------------------------------------------------------------

@pytest.fixture
def iam_policy_all_users() -> dict:
    """Policy IAM de GCP con binding allUsers (acceso público CRITICAL)."""
    return {
        "bindings": [
            {
                "role": "roles/viewer",
                "members": ["allUsers"],
            },
            {
                "role": "roles/storage.objectViewer",
                "members": ["user:admin@example.com"],
            },
        ]
    }


@pytest.fixture
def iam_policy_segura() -> dict:
    """Policy IAM de GCP sin bindings públicos."""
    return {
        "bindings": [
            {
                "role": "roles/viewer",
                "members": ["user:dev@example.com", "serviceAccount:sa@project.iam.gserviceaccount.com"],
            }
        ]
    }


@pytest.fixture
def cloud_run_service_allusers() -> dict:
    """Servicio Cloud Run con invocación pública (allUsers)."""
    return {
        "metadata": {"name": "mi-api", "namespace": "123456789"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "image": "gcr.io/myproject/mi-api:latest",
                        "env": [],
                    }]
                }
            }
        },
        "status": {"url": "https://mi-api-abc123-uc.a.run.app"},
    }


@pytest.fixture
def cloud_run_iam_allusers() -> dict:
    """IAM policy de Cloud Run que permite invocación por allUsers."""
    return {
        "bindings": [
            {
                "role": "roles/run.invoker",
                "members": ["allUsers"],
            }
        ]
    }


@pytest.fixture
def cloud_function_secreto_env() -> dict:
    """Cloud Function con secretos en variables de entorno."""
    return {
        "name": "projects/myproj/locations/us-central1/functions/mi-funcion",
        "httpsTrigger": {"url": "https://us-central1-myproj.cloudfunctions.net/mi-funcion"},
        "environmentVariables": {
            "DB_PASSWORD": "supersecret123",
            "API_KEY": "sk_live_ABCDEFGHIJKLMN",
        },
        "serviceAccountEmail": "myproj@appspot.gserviceaccount.com",
        "ingressSettings": "ALLOW_ALL",
    }


@pytest.fixture
def compute_instancia_serial_port() -> dict:
    """Instancia Compute Engine con puerto serie habilitado."""
    return {
        "name": "vm-insegura",
        "zone": "projects/myproj/zones/us-central1-a",
        "metadata": {
            "items": [
                {"key": "serial-port-enable", "value": "true"},
            ]
        },
        "serviceAccounts": [{"email": "myproj@developer.gserviceaccount.com"}],
        "status": "RUNNING",
    }


@pytest.fixture
def bucket_publico() -> dict:
    """Bucket GCS con IAM policy que incluye allUsers."""
    return {
        "kind": "storage#bucket",
        "name": "mi-bucket-publico",
        "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}},
    }
