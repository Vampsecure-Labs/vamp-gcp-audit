# © VampSecure Studios — VampSecure Labs Security Research Division
#!/usr/bin/env python3
"""
vamp_gcp_audit.py — Auditor de Seguridad de Entornos Google Cloud Platform
===========================================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v1.0

DESCRIPCIÓN GENERAL
-------------------
Auditor profesional de configuraciones de seguridad en GCP. Detecta
misconfiguraciones críticas en IAM, buckets GCS, clústeres GKE,
Cloud Functions, reglas de firewall y configuraciones de proyecto,
usando únicamente la API REST de GCP (sin SDKs de google-cloud-*).

MÓDULOS DE AUDITORÍA
--------------------
  Módulo 1: IAM & Service Accounts
    · Service accounts con roles excesivos (owner/editor)
    · Keys antiguas (>90 días) y SA con múltiples keys activas
    · SA deshabilitadas con bindings IAM activos

  Módulo 2: GCS Bucket Security
    · Buckets públicos (allUsers / allAuthenticatedUsers)
    · ACLs legacy activas (uniformBucketLevelAccess deshabilitado)
    · Logging y versioning deshabilitados
    · Nombres que sugieren contenido sensible

  Módulo 3: GKE Cluster Security
    · RBAC legacy (legacyAbac), autenticación estática
    · Network Policy deshabilitada, Shielded Nodes deshabilitados
    · Endpoint público sin restricción de redes autorizadas

  Módulo 4: Cloud Functions Security
    · Funciones HTTP sin forzar HTTPS
    · Funciones sin autenticación (invoker = allUsers)
    · Variables de entorno con credenciales embebidas
    · Funciones usando SA por defecto de Compute

  Módulo 5: Firewall Rules
    · Reglas 0.0.0.0/0 en puertos sensibles (SSH, RDP, DB...)
    · Reglas allow-all desde internet
    · Reglas de internet sin logging habilitado

  Módulo 6: Project-Level Risks
    · APIs peligrosas habilitadas (Deployment Manager, Cloud Shell)
    · Audit logging insuficiente
    · Ausencia de org policy contra allUsers en GCS

FORMATOS DE SALIDA
------------------
  Consola  · Rich con paneles y tabla resumen
  JSON     · --json FILE   (estructura completa de hallazgos)
  HTML     · --html FILE   (informe dark-theme standalone)

DEPENDENCIAS
------------
  aiohttp >= 3.9.0
  rich >= 13.7.0
  Python >= 3.11

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
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Optional

import aiohttp
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ---------------------------------------------------------------------------
# Constantes y configuración global
# ---------------------------------------------------------------------------

VERSION   = "1.0"
TOOL_NAME = "vamp-gcp-audit"

console = Console()

# Orden de severidades para ordenar y comparar
SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "INFO":     4,
}

SEVERITY_COLOR: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold magenta",
    "LOW":      "cyan",
    "INFO":     "green",
}

# Endpoints base de las APIs REST de GCP
GCP_CRM_API  = "https://cloudresourcemanager.googleapis.com"
GCP_IAM_API  = "https://iam.googleapis.com"
GCP_GCS_API  = "https://storage.googleapis.com"
GCP_COMP_API = "https://compute.googleapis.com"
GCP_FUNC_API = "https://cloudfunctions.googleapis.com"
GCP_GKE_API  = "https://container.googleapis.com"
GCP_SVC_API  = "https://serviceusage.googleapis.com"
GCP_LOG_API  = "https://logging.googleapis.com"
GCP_ORG_API  = "https://orgpolicy.googleapis.com"

# Puertos sensibles para detección en reglas de firewall
SENSITIVE_PORTS: dict[int, str] = {
    22:    "SSH",
    23:    "Telnet",
    3389:  "RDP",
    5432:  "PostgreSQL",
    3306:  "MySQL",
    27017: "MongoDB",
    6379:  "Redis",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch (cluster)",
    5984:  "CouchDB",
    8500:  "Consul",
    2375:  "Docker daemon (sin TLS)",
    2376:  "Docker daemon (TLS)",
    4848:  "GlassFish Admin",
    7474:  "Neo4j",
    8088:  "YARN ResourceManager",
    10250: "Kubelet API",
}

# Palabras clave que sugieren contenido sensible en nombres de bucket
SENSITIVE_BUCKET_KEYWORDS = frozenset({
    "backup", "backups", "secret", "secrets", "key", "keys",
    "prod", "production", "db", "database", "dump", "dumps",
    "logs", "log", "cred", "credentials", "cert", "certs",
    "private", "internal", "config", "configs",
})

# Palabras clave de secretos en variables de entorno de Cloud Functions
SECRET_ENV_KEYWORDS = frozenset({
    "password", "passwd", "pwd", "secret", "key", "token",
    "api_key", "apikey", "auth", "credential", "credentials",
    "private_key", "privatekey", "access_key", "accesskey",
    "client_secret", "client_id", "database_url", "db_url",
    "connection_string", "conn_str",
})

# Roles IAM excesivos a nivel proyecto
EXCESSIVE_ROLES = frozenset({
    "roles/owner",
    "roles/editor",
})

# APIs peligrosas que deberían auditarse si están habilitadas
DANGEROUS_APIS = {
    "deploymentmanager.googleapis.com": (
        "Cloud Deployment Manager puede ser abusado para escalar privilegios IAM",
        "MEDIUM",
    ),
    "cloudshell.googleapis.com": (
        "Cloud Shell API proporciona acceso interactivo que puede eludir controles",
        "LOW",
    ),
    "iam.googleapis.com": None,  # Necesaria, no alertar
    "cloudresourcemanager.googleapis.com": None,
}

BANNER = r"""
 ____   ____  ____       ___  __  _  ____        __   __  _  ____   ____  _____
 \ \ \ / / \ |  \/|    / ___|/ _|| ||  _ \      /  | |  || ||    \ |_ _||_   _|
  \ \ V / _ \| |\/|   | |  _| |_ | || |_) |    / _ | | || || |  | || |   | |
   \ | / ___ \ |  |   | |_| |  _|| ||  __/    / ___ || || || |  | || |   | |
    \_/_/   \_|_|  |    \____|_|  |_||_|      /_/   \_||_||_||____/|___| |_|

  ██████████ ██████  ██████      █████  ██    ██ ██████  ██ ████████
  ██        ██      ██   ██    ██   ██ ██    ██ ██   ██ ██    ██
  ██  ████  ██      ██████     ███████ ██    ██ ██   ██ ██    ██
  ██     ██ ██      ██         ██   ██ ██    ██ ██   ██ ██    ██
  ██████████  ██████ ██        ██   ██  ██████  ██████  ██    ██

  ____   ____    _    __  __ ____  _____ ____ _   _ ____  _____   _        _    ____ ____
 \ \ / / _  |  / \  |  \/  |  _ \/ ____/ ___| | | |  _ \| ____| | |      / \  | __ ) ___|
  \ V / (_| | / _ \ | |\/| | |_) \___ \| |___| | | | |_) |  _|   | |     / _ \ |  _ \___ \
   | |  \__, |/ ___ \| |  | |  __/ ___) |___  | |_| |  _ <| |___  | |___ / ___ \| |_) |__) |
   |_|     /_/_/   \_|_|  |_|_|   |____/\____|\___/|_| \_|_____| |_____/_/   \_|____/____/
     by Antonio Hernandez "Belky" — VampSecure Studios · vamp-gcp-audit v{ver} · GCP Security Auditor
     ─────────────────────────────────────────────────────────────────────
     USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
""".format(ver=VERSION)


# ---------------------------------------------------------------------------
# Dataclass Finding — hallazgo de seguridad
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Representa un hallazgo de seguridad detectado por la herramienta."""

    tool:           str               # Nombre de la herramienta (TOOL_NAME)
    severity:       str               # CRITICAL | HIGH | MEDIUM | LOW | INFO
    type:           str               # Tipo/categoría del hallazgo
    title:          str               # Título breve del hallazgo
    description:    str               # Descripción detallada
    affected:       str               # Recurso afectado (URI o nombre)
    recommendation: str               # Acción de remediación recomendada
    module:         str = ""          # Módulo que generó el hallazgo
    extra:          dict = field(default_factory=dict)  # Datos adicionales

    def to_dict(self) -> dict:
        """Serializa el hallazgo a diccionario para JSON."""
        return {
            "tool":           self.tool,
            "severity":       self.severity,
            "type":           self.type,
            "title":          self.title,
            "description":    self.description,
            "affected":       self.affected,
            "recommendation": self.recommendation,
            "module":         self.module,
            "extra":          self.extra,
        }


# ---------------------------------------------------------------------------
# GCPClient — cliente HTTP autenticado para la API REST de GCP
# ---------------------------------------------------------------------------

class GCPClient:
    """
    Wrapper asíncrono para las APIs REST de GCP.

    Soporta dos métodos de autenticación:
      1. Fichero de credenciales de service account (JSON)
      2. Token ADC vía 'gcloud auth print-access-token'
    """

    def __init__(
        self,
        project_id: str,
        credentials_file: Optional[str] = None,
        session: Optional[aiohttp.ClientSession] = None,
    ) -> None:
        self.project_id  = project_id
        self._creds_file = credentials_file
        self._token:  Optional[str] = None
        self._session: Optional[aiohttp.ClientSession] = session
        self._own_session = session is None

    # ------------------------------------------------------------------
    # Gestión del token de acceso
    # ------------------------------------------------------------------

    async def _get_token_from_gcloud(self) -> str:
        """Obtiene un token de acceso usando 'gcloud auth print-access-token'."""
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["gcloud", "auth", "print-access-token"],
                    capture_output=True, text=True, timeout=15,
                ),
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"gcloud auth print-access-token falló: {result.stderr.strip()}"
                )
            return result.stdout.strip()
        except FileNotFoundError:
            raise RuntimeError(
                "gcloud no está instalado o no está en el PATH. "
                "Instala Google Cloud SDK o usa --credentials."
            )

    async def _get_token_from_service_account(self, creds_path: str) -> str:
        """
        Obtiene un token OAuth2 usando un fichero de credenciales de service account.
        Implementa el flujo JWT→token de Google sin SDKs externos.
        """
        import base64
        import hashlib
        import hmac
        import time

        with open(creds_path) as f:
            creds = json.load(f)

        if creds.get("type") != "service_account":
            raise RuntimeError(
                f"El fichero {creds_path} no es una service account key de GCP."
            )

        # Construir el JWT (RS256) para el intercambio de token
        now = int(time.time())
        header  = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "iss":   creds["client_email"],
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "aud":   "https://oauth2.googleapis.com/token",
            "exp":   now + 3600,
            "iat":   now,
        }

        def b64url(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

        header_b64  = b64url(json.dumps(header).encode())
        payload_b64 = b64url(json.dumps(payload).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode()

        # Firma con la clave privada RSA del service account usando cryptography (stdlib no tiene RSA)
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding

            private_key = serialization.load_pem_private_key(
                creds["private_key"].encode(), password=None
            )
            signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        except ImportError:
            raise RuntimeError(
                "El paquete 'cryptography' es necesario para autenticación por service account JSON. "
                "Instálalo con: pip install cryptography"
            )

        jwt_token = f"{header_b64}.{payload_b64}.{b64url(signature)}"

        # Intercambiar JWT por access token
        async with self._session.post(
            "https://oauth2.googleapis.com/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion":  jwt_token,
            },
        ) as resp:
            data = await resp.json()
            if "access_token" not in data:
                raise RuntimeError(
                    f"No se pudo obtener el access token: {data.get('error_description', data)}"
                )
            return data["access_token"]

    async def authenticate(self) -> None:
        """Inicializa la sesión HTTP y obtiene un token de acceso válido."""
        if self._own_session:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(ssl=True),
            )

        if self._creds_file:
            self._token = await self._get_token_from_service_account(self._creds_file)
        else:
            self._token = await self._get_token_from_gcloud()

    async def close(self) -> None:
        """Cierra la sesión HTTP si fue creada por este cliente."""
        if self._own_session and self._session:
            await self._session.close()

    # ------------------------------------------------------------------
    # Métodos de petición HTTP
    # ------------------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        """Devuelve las cabeceras de autenticación Bearer."""
        return {"Authorization": f"Bearer {self._token}"}

    async def get(self, url: str, params: Optional[dict] = None) -> dict:
        """
        Realiza una petición GET autenticada a la API de GCP.
        Devuelve el cuerpo JSON como diccionario.
        Lanza RuntimeError si la respuesta indica un error HTTP.
        """
        async with self._session.get(url, headers=self._auth_headers(), params=params) as resp:
            body = await resp.json()
            if resp.status not in (200, 404):
                error_msg = body.get("error", {}).get("message", str(body))
                raise RuntimeError(f"HTTP {resp.status} en {url}: {error_msg}")
            return body

    async def get_paginated(
        self, url: str, key: str, params: Optional[dict] = None
    ) -> list:
        """
        Realiza peticiones paginadas a una API GCP que devuelve 'nextPageToken'.
        Agrega todos los elementos bajo la clave 'key' y los devuelve en una lista.
        """
        items: list = []
        page_params = dict(params or {})
        while True:
            data = await self.get(url, params=page_params)
            items.extend(data.get(key, []))
            next_token = data.get("nextPageToken")
            if not next_token:
                break
            page_params["pageToken"] = next_token
        return items

    async def post(self, url: str, body: dict) -> dict:
        """Realiza una petición POST autenticada con cuerpo JSON."""
        async with self._session.post(
            url, headers=self._auth_headers(), json=body
        ) as resp:
            return await resp.json()


# ---------------------------------------------------------------------------
# Módulo 1: Auditoría de IAM y Service Accounts
# ---------------------------------------------------------------------------

async def audit_iam(client: GCPClient) -> list[Finding]:
    """
    Audita la configuración de IAM y Service Accounts del proyecto GCP.

    Comprobaciones:
      - Service accounts con roles básicos excesivos (owner, editor) a nivel proyecto
      - Keys de SA antiguas (>90 días) o múltiples keys activas (>2)
      - SA deshabilitadas con bindings IAM activos
    """
    findings: list[Finding] = []
    project = client.project_id

    # Obtener todos los service accounts del proyecto
    sa_url = f"{GCP_IAM_API}/v1/projects/{project}/serviceAccounts"
    try:
        service_accounts: list[dict] = await client.get_paginated(
            sa_url, "accounts"
        )
    except RuntimeError as exc:
        findings.append(Finding(
            tool=TOOL_NAME, severity="INFO", type="iam-error",
            title="No se pudo listar los service accounts",
            description=str(exc), affected=f"projects/{project}",
            recommendation="Verifica permisos iam.serviceAccounts.list",
            module="IAM",
        ))
        return findings

    # Obtener la política IAM del proyecto (bindings de roles a nivel proyecto)
    policy_url = f"{GCP_CRM_API}/v1/projects/{project}:getIamPolicy"
    try:
        policy_resp = await client.post(policy_url, {})
        bindings: list[dict] = policy_resp.get("bindings", [])
    except RuntimeError as exc:
        bindings = []
        findings.append(Finding(
            tool=TOOL_NAME, severity="INFO", type="iam-error",
            title="No se pudo obtener la política IAM del proyecto",
            description=str(exc), affected=f"projects/{project}",
            recommendation="Verifica permisos resourcemanager.projects.getIamPolicy",
            module="IAM",
        ))

    # Mapear miembros con roles excesivos
    excessive_members: dict[str, list[str]] = {}
    for binding in bindings:
        role = binding.get("role", "")
        if role in EXCESSIVE_ROLES:
            for member in binding.get("members", []):
                excessive_members.setdefault(member, []).append(role)

    # Conjunto de emails de SA con bindings IAM activos
    sa_emails_in_policy: set[str] = set()
    for binding in bindings:
        for member in binding.get("members", []):
            if member.startswith("serviceAccount:"):
                sa_emails_in_policy.add(member.split(":", 1)[1])

    now = datetime.now(tz=timezone.utc)

    for sa in service_accounts:
        sa_email    = sa.get("email", "")
        sa_name     = sa.get("name", "")
        sa_disabled = sa.get("disabled", False)
        display     = sa.get("displayName", sa_email)

        # 1a. SA con roles excesivos asignados directamente al proyecto
        member_key = f"serviceAccount:{sa_email}"
        if member_key in excessive_members:
            roles_str = ", ".join(excessive_members[member_key])
            findings.append(Finding(
                tool=TOOL_NAME, severity="CRITICAL", type="iam-excessive-role",
                title=f"Service Account con rol excesivo: {roles_str}",
                description=(
                    f"La service account '{display}' ({sa_email}) tiene asignado "
                    f"el rol '{roles_str}' a nivel de proyecto. Esto le otorga acceso "
                    f"completo o de edición a todos los recursos del proyecto."
                ),
                affected=sa_email,
                recommendation=(
                    "Aplica el principio de mínimo privilegio. Reemplaza roles/owner "
                    "o roles/editor por roles predefinidos específicos al servicio que "
                    "necesita la SA. Revisa si la SA es usada activamente."
                ),
                module="IAM",
            ))

        # 1b. SA deshabilitada con bindings IAM activos
        if sa_disabled and sa_email in sa_emails_in_policy:
            findings.append(Finding(
                tool=TOOL_NAME, severity="MEDIUM", type="iam-disabled-sa-binding",
                title="SA deshabilitada con bindings IAM activos",
                description=(
                    f"La service account '{display}' ({sa_email}) está deshabilitada "
                    f"pero sigue teniendo bindings de rol asignados en la política IAM "
                    f"del proyecto. Los bindings huérfanos dificultan la auditoría."
                ),
                affected=sa_email,
                recommendation=(
                    "Elimina los bindings IAM de la SA deshabilitada o, si ya no es "
                    "necesaria, elimínala completamente del proyecto."
                ),
                module="IAM",
            ))

        # 1c. Auditoría de keys de la SA
        keys_url = f"{GCP_IAM_API}/v1/{sa_name}/keys?keyTypes=USER_MANAGED"
        try:
            keys_resp = await client.get(keys_url)
            keys: list[dict] = keys_resp.get("keys", [])
        except RuntimeError:
            keys = []

        active_keys = [k for k in keys if not k.get("disabled", False)]

        # SA con múltiples keys activas (>2) — superficie de ataque ampliada
        if len(active_keys) > 2:
            findings.append(Finding(
                tool=TOOL_NAME, severity="MEDIUM", type="iam-multiple-keys",
                title=f"SA con {len(active_keys)} keys activas (>2)",
                description=(
                    f"La service account '{display}' ({sa_email}) tiene "
                    f"{len(active_keys)} keys de usuario activas. Cada key adicional "
                    f"amplía la superficie de ataque si alguna es comprometida."
                ),
                affected=sa_email,
                recommendation=(
                    "Reduce el número de keys activas al mínimo necesario. Rota las "
                    "keys periódicamente y elimina las que no se usen. Prefiere Workload "
                    "Identity Federation sobre keys descargables."
                ),
                module="IAM",
                extra={"active_keys_count": len(active_keys)},
            ))

        # Keys antiguas: creadas hace más de 90 días
        for key in active_keys:
            created_str = key.get("validAfterTime", "")
            if not created_str:
                continue
            try:
                created = datetime.fromisoformat(
                    created_str.replace("Z", "+00:00")
                )
                age_days = (now - created).days
                if age_days > 90:
                    findings.append(Finding(
                        tool=TOOL_NAME, severity="HIGH", type="iam-old-key",
                        title=f"Key de SA con {age_days} días sin rotar",
                        description=(
                            f"La service account '{display}' ({sa_email}) tiene una "
                            f"key creada el {created.date()} ({age_days} días). Las keys "
                            f"no rotadas incrementan el riesgo ante una filtración."
                        ),
                        affected=f"{sa_email} → {key.get('name', '').split('/')[-1]}",
                        recommendation=(
                            "Rota las keys de SA cada 90 días como máximo. Considera "
                            "migrar a Workload Identity Federation para eliminar la "
                            "necesidad de keys descargables."
                        ),
                        module="IAM",
                        extra={"key_age_days": age_days, "created": created_str},
                    ))
            except (ValueError, TypeError):
                pass

    return findings


# ---------------------------------------------------------------------------
# Módulo 2: Auditoría de GCS Buckets
# ---------------------------------------------------------------------------

async def audit_gcs(client: GCPClient) -> list[Finding]:
    """
    Audita la configuración de seguridad de los buckets de Google Cloud Storage.

    Comprobaciones:
      - Buckets accesibles públicamente (allUsers / allAuthenticatedUsers)
      - ACLs legacy activas (uniformBucketLevelAccess deshabilitado)
      - Logging y versioning deshabilitados
      - Nombres que sugieren contenido sensible
    """
    findings: list[Finding] = []
    project = client.project_id

    # Listar todos los buckets del proyecto
    buckets_url = f"{GCP_GCS_API}/storage/v1/b"
    try:
        buckets: list[dict] = await client.get_paginated(
            buckets_url, "items",
            params={"project": project, "projection": "full"},
        )
    except RuntimeError as exc:
        findings.append(Finding(
            tool=TOOL_NAME, severity="INFO", type="gcs-error",
            title="No se pudo listar los buckets GCS",
            description=str(exc), affected=f"projects/{project}",
            recommendation="Verifica permisos storage.buckets.list",
            module="GCS",
        ))
        return findings

    if not buckets:
        findings.append(Finding(
            tool=TOOL_NAME, severity="INFO", type="gcs-no-buckets",
            title="No se encontraron buckets en el proyecto",
            description="El proyecto no tiene buckets GCS o no hay acceso para listarlos.",
            affected=f"projects/{project}",
            recommendation="Sin acción requerida si el proyecto no usa GCS.",
            module="GCS",
        ))
        return findings

    for bucket in buckets:
        bucket_name = bucket.get("name", "")
        bucket_id   = bucket.get("id", bucket_name)

        # 2a. Comprobar si el nombre sugiere contenido sensible
        name_lower = bucket_name.lower()
        for keyword in SENSITIVE_BUCKET_KEYWORDS:
            if keyword in name_lower:
                findings.append(Finding(
                    tool=TOOL_NAME, severity="LOW", type="gcs-sensitive-name",
                    title=f"Bucket con nombre que sugiere contenido sensible: '{keyword}'",
                    description=(
                        f"El bucket '{bucket_name}' contiene la palabra '{keyword}' en su "
                        f"nombre, lo que puede indicar presencia de datos sensibles. "
                        f"Requiere revisión manual de su contenido y configuración."
                    ),
                    affected=f"gs://{bucket_name}",
                    recommendation=(
                        "Verifica el contenido del bucket y asegúrate de que tiene "
                        "los controles de acceso apropiados para su nivel de sensibilidad."
                    ),
                    module="GCS",
                ))
                break  # Solo un hallazgo por bucket por esta categoría

        # 2b. Comprobar IAM policy del bucket buscando acceso público
        iam_url = f"{GCP_GCS_API}/storage/v1/b/{bucket_name}/iam"
        try:
            iam_policy = await client.get(iam_url)
            for binding in iam_policy.get("bindings", []):
                role    = binding.get("role", "")
                members = binding.get("members", [])
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    public_member = "allUsers" if "allUsers" in members else "allAuthenticatedUsers"
                    severity = "CRITICAL" if public_member == "allUsers" else "HIGH"
                    findings.append(Finding(
                        tool=TOOL_NAME, severity=severity, type="gcs-public-access",
                        title=f"Bucket público: {public_member} con {role}",
                        description=(
                            f"El bucket '{bucket_name}' otorga el rol '{role}' a "
                            f"'{public_member}', haciendo que su contenido sea accesible "
                            f"{'por cualquier usuario de internet' if public_member == 'allUsers' else 'por cualquier cuenta de Google'}."
                        ),
                        affected=f"gs://{bucket_name}",
                        recommendation=(
                            f"Revoca el binding '{public_member}:{role}' inmediatamente. "
                            "Si el acceso público es requerido, usa Cloud CDN o un proxy "
                            "controlado. Activa la política org 'constraints/iam.allowedPolicyMemberDomains'."
                        ),
                        module="GCS",
                        extra={"public_member": public_member, "role": role},
                    ))
        except RuntimeError:
            pass  # Sin acceso a la IAM policy del bucket, continuar

        # 2c. Uniform Bucket-Level Access deshabilitado (ACLs legacy activas)
        iam_config = bucket.get("iamConfiguration", {})
        ubla = iam_config.get("uniformBucketLevelAccess", {})
        if not ubla.get("enabled", False):
            findings.append(Finding(
                tool=TOOL_NAME, severity="MEDIUM", type="gcs-legacy-acl",
                title="Bucket con ACLs legacy activas (Uniform Access deshabilitado)",
                description=(
                    f"El bucket '{bucket_name}' tiene 'Uniform Bucket-Level Access' "
                    f"deshabilitado, lo que permite el uso de ACLs de objeto legacy. "
                    f"Las ACLs legacy son más difíciles de auditar y pueden dar acceso "
                    f"inesperado a objetos individuales."
                ),
                affected=f"gs://{bucket_name}",
                recommendation=(
                    "Habilita Uniform Bucket-Level Access para gestionar todos los "
                    "permisos únicamente a través de IAM. Migra las ACLs de objeto "
                    "existentes a bindings IAM equivalentes antes de activarlo."
                ),
                module="GCS",
            ))

        # 2d. Logging deshabilitado
        logging_cfg = bucket.get("logging", {})
        if not logging_cfg.get("logBucket"):
            findings.append(Finding(
                tool=TOOL_NAME, severity="LOW", type="gcs-no-logging",
                title="Bucket sin logging de acceso habilitado",
                description=(
                    f"El bucket '{bucket_name}' no tiene logging de acceso configurado. "
                    f"Sin logs, es imposible auditar quién accedió o modificó los objetos."
                ),
                affected=f"gs://{bucket_name}",
                recommendation=(
                    "Habilita el logging de acceso al bucket especificando un bucket "
                    "de destino para los logs. Considera también Cloud Audit Logs para "
                    "operaciones de datos."
                ),
                module="GCS",
            ))

        # 2e. Versioning deshabilitado (protección ante ransomware)
        versioning = bucket.get("versioning", {})
        if not versioning.get("enabled", False):
            findings.append(Finding(
                tool=TOOL_NAME, severity="LOW", type="gcs-no-versioning",
                title="Bucket sin versioning habilitado",
                description=(
                    f"El bucket '{bucket_name}' no tiene versioning activado. Sin él, "
                    f"los objetos sobrescritos o eliminados no son recuperables, lo que "
                    f"aumenta el impacto ante ransomware o borrado accidental."
                ),
                affected=f"gs://{bucket_name}",
                recommendation=(
                    "Habilita el versioning en buckets que almacenen datos críticos. "
                    "Combínalo con una política de ciclo de vida para eliminar versiones "
                    "antiguas y controlar costes."
                ),
                module="GCS",
            ))

    return findings


# ---------------------------------------------------------------------------
# Módulo 3: Auditoría de clústeres GKE
# ---------------------------------------------------------------------------

async def audit_gke(client: GCPClient) -> list[Finding]:
    """
    Audita la configuración de seguridad de los clústeres de Google Kubernetes Engine.

    Comprobaciones:
      - RBAC legacy (legacyAbac), autenticación estática
      - Network Policy deshabilitada, Shielded Nodes deshabilitados
      - Endpoint público sin restricción de IPs autorizadas
    """
    findings: list[Finding] = []
    project = client.project_id

    clusters_url = f"{GCP_GKE_API}/v1/projects/{project}/locations/-/clusters"
    try:
        data = await client.get(clusters_url)
        clusters: list[dict] = data.get("clusters", [])
    except RuntimeError as exc:
        findings.append(Finding(
            tool=TOOL_NAME, severity="INFO", type="gke-error",
            title="No se pudieron listar los clústeres GKE",
            description=str(exc), affected=f"projects/{project}",
            recommendation="Verifica permisos container.clusters.list",
            module="GKE",
        ))
        return findings

    if not clusters:
        findings.append(Finding(
            tool=TOOL_NAME, severity="INFO", type="gke-no-clusters",
            title="No se encontraron clústeres GKE en el proyecto",
            description="El proyecto no tiene clústeres GKE o no hay acceso para listarlos.",
            affected=f"projects/{project}",
            recommendation="Sin acción requerida si el proyecto no usa GKE.",
            module="GKE",
        ))
        return findings

    for cluster in clusters:
        cluster_name     = cluster.get("name", "")
        cluster_location = cluster.get("location", "")
        cluster_full     = f"projects/{project}/locations/{cluster_location}/clusters/{cluster_name}"

        # 3a. RBAC legacy habilitado
        legacy_abac = cluster.get("legacyAbac", {})
        if legacy_abac.get("enabled", False):
            findings.append(Finding(
                tool=TOOL_NAME, severity="HIGH", type="gke-legacy-abac",
                title="Clúster con RBAC legacy (legacyAbac) habilitado",
                description=(
                    f"El clúster '{cluster_name}' tiene legacyAbac habilitado. "
                    f"El RBAC legacy otorga permisos amplios a todos los service accounts "
                    f"y usuarios autenticados, ignorando las políticas RBAC de Kubernetes."
                ),
                affected=cluster_full,
                recommendation=(
                    "Deshabilita legacyAbac y migra a Kubernetes RBAC. "
                    "Usa roles y ClusterRoles específicos para cada workload."
                ),
                module="GKE",
            ))

        # 3b. Autenticación estática habilitada (usuario/contraseña)
        master_auth = cluster.get("masterAuth", {})
        if master_auth.get("username"):
            findings.append(Finding(
                tool=TOOL_NAME, severity="CRITICAL", type="gke-static-auth",
                title="Clúster con autenticación estática habilitada (usuario/contraseña)",
                description=(
                    f"El clúster '{cluster_name}' tiene autenticación básica habilitada "
                    f"(masterAuth.username no vacío). Las credenciales estáticas son un "
                    f"vector de ataque ante fuerza bruta o filtración de credenciales."
                ),
                affected=cluster_full,
                recommendation=(
                    "Deshabilita la autenticación básica estableciendo masterAuth.username "
                    "a vacío. Usa en su lugar autenticación basada en certificados o OIDC."
                ),
                module="GKE",
            ))

        # 3c. Network Policy deshabilitada
        network_policy = cluster.get("networkPolicy", {})
        if not network_policy.get("enabled", False):
            findings.append(Finding(
                tool=TOOL_NAME, severity="MEDIUM", type="gke-no-netpol",
                title="Clúster sin Network Policy habilitada",
                description=(
                    f"El clúster '{cluster_name}' no tiene Network Policy habilitada. "
                    f"Sin Network Policies, cualquier Pod puede comunicarse con cualquier "
                    f"otro Pod del clúster, facilitando el movimiento lateral."
                ),
                affected=cluster_full,
                recommendation=(
                    "Habilita el plugin de Network Policy (Calico o Dataplane V2) y "
                    "define NetworkPolicy resources para restringir el tráfico entre Pods "
                    "al mínimo necesario (default-deny + reglas explícitas)."
                ),
                module="GKE",
            ))

        # 3d. Shielded Nodes deshabilitados
        shielded_nodes = cluster.get("shieldedNodes", {})
        if not shielded_nodes.get("enabled", False):
            findings.append(Finding(
                tool=TOOL_NAME, severity="MEDIUM", type="gke-no-shielded",
                title="Clúster sin Shielded Nodes habilitados",
                description=(
                    f"El clúster '{cluster_name}' no tiene Shielded Nodes activos. "
                    f"Shielded Nodes protegen frente a rootkits y bootkits en el nodo "
                    f"mediante Secure Boot y vTPM."
                ),
                affected=cluster_full,
                recommendation=(
                    "Habilita Shielded Nodes en el clúster. Para clústeres existentes, "
                    "es necesario recrear los node pools. Nuevos clústeres deben crearse "
                    "con --enable-shielded-nodes."
                ),
                module="GKE",
            ))

        # 3e. Endpoint público sin restricción de IPs autorizadas
        master_auth_nets = cluster.get("masterAuthorizedNetworksConfig", {})
        private_cluster  = cluster.get("privateClusterConfig", {})
        endpoint_public  = not private_cluster.get("enablePrivateEndpoint", False)
        master_nets_enabled = master_auth_nets.get("enabled", False)

        if endpoint_public and not master_nets_enabled:
            findings.append(Finding(
                tool=TOOL_NAME, severity="HIGH", type="gke-public-endpoint",
                title="API server GKE público sin restricción de IPs autorizadas",
                description=(
                    f"El clúster '{cluster_name}' tiene el endpoint del API server "
                    f"público y no tiene masterAuthorizedNetworksConfig habilitado. "
                    f"Cualquier IP de internet puede intentar conectarse al API server."
                ),
                affected=cluster_full,
                recommendation=(
                    "Habilita masterAuthorizedNetworksConfig con las CIDRs de los equipos "
                    "y CI/CD que necesitan acceso. Considera migrar a un clúster privado "
                    "con acceso al API server solo por VPN o Cloud Interconnect."
                ),
                module="GKE",
            ))

        # 3f. Nodos sin Secure Boot
        node_pools = cluster.get("nodePools", [])
        for pool in node_pools:
            pool_name   = pool.get("name", "")
            shielded_ic = pool.get("config", {}).get("shieldedInstanceConfig", {})
            if not shielded_ic.get("enableSecureBoot", False):
                findings.append(Finding(
                    tool=TOOL_NAME, severity="LOW", type="gke-no-secureboot",
                    title=f"Node pool '{pool_name}' sin Secure Boot",
                    description=(
                        f"El node pool '{pool_name}' del clúster '{cluster_name}' "
                        f"no tiene Secure Boot habilitado. Secure Boot verifica la "
                        f"integridad del software del nodo durante el arranque."
                    ),
                    affected=f"{cluster_full}/nodePools/{pool_name}",
                    recommendation=(
                        "Habilita enableSecureBoot en la configuración del node pool. "
                        "Requiere recrear los nodos existentes del pool."
                    ),
                    module="GKE",
                ))

    return findings


# ---------------------------------------------------------------------------
# Módulo 4: Auditoría de Cloud Functions
# ---------------------------------------------------------------------------

async def audit_functions(client: GCPClient) -> list[Finding]:
    """
    Audita la configuración de seguridad de Cloud Functions (v1 y v2).

    Comprobaciones:
      - Funciones HTTP sin forzar HTTPS
      - Funciones sin autenticación (invoker = allUsers)
      - Variables de entorno con credenciales embebidas
      - Funciones usando SA por defecto de Compute
    """
    findings: list[Finding] = []
    project = client.project_id

    # Cloud Functions v2
    funcs_url = f"{GCP_FUNC_API}/v2/projects/{project}/locations/-/functions"
    try:
        functions: list[dict] = await client.get_paginated(funcs_url, "functions")
    except RuntimeError as exc:
        findings.append(Finding(
            tool=TOOL_NAME, severity="INFO", type="functions-error",
            title="No se pudieron listar las Cloud Functions",
            description=str(exc), affected=f"projects/{project}",
            recommendation="Verifica permisos cloudfunctions.functions.list",
            module="Functions",
        ))
        return findings

    if not functions:
        findings.append(Finding(
            tool=TOOL_NAME, severity="INFO", type="functions-none",
            title="No se encontraron Cloud Functions en el proyecto",
            description="El proyecto no tiene Cloud Functions o no hay acceso para listarlas.",
            affected=f"projects/{project}",
            recommendation="Sin acción requerida si el proyecto no usa Cloud Functions.",
            module="Functions",
        ))
        return findings

    # SA por defecto de Compute Engine (patrón conocido)
    compute_default_sa_pattern = re.compile(
        r"^\d+-compute@developer\.gserviceaccount\.com$"
    )

    for func in functions:
        func_name  = func.get("name", "")
        func_short = func_name.split("/")[-1]
        service_cfg = func.get("serviceConfig", {})
        build_cfg   = func.get("buildConfig", {})

        # 4a. Comprobar si la función tiene trigger HTTP sin HTTPS forzado
        # En v2, el trigger es 'serviceConfig.uri' y puede tener httpsTrigger
        labels = func.get("labels", {})
        trigger = func.get("httpsTrigger", {}) or {}
        security_level = trigger.get("securityLevel", "")
        # En v2 las funciones con trigger HTTP exponen una URL en serviceConfig
        func_uri = service_cfg.get("uri", "")

        if func_uri and security_level and security_level != "SECURE_ALWAYS":
            findings.append(Finding(
                tool=TOOL_NAME, severity="MEDIUM", type="functions-no-https",
                title=f"Cloud Function '{func_short}' no fuerza HTTPS",
                description=(
                    f"La función '{func_short}' tiene securityLevel='{security_level}' "
                    f"en lugar de SECURE_ALWAYS. Esto permite invocaciones HTTP en claro, "
                    f"exponiendo datos en tránsito."
                ),
                affected=func_name,
                recommendation=(
                    "Establece httpsTrigger.securityLevel = SECURE_ALWAYS para redirigir "
                    "automáticamente las peticiones HTTP a HTTPS."
                ),
                module="Functions",
            ))

        # 4b. Comprobar si la función es invocable por allUsers (sin autenticación)
        # Esto requiere revisar la IAM policy de la función
        func_iam_url = f"{GCP_FUNC_API}/v2/{func_name}:getIamPolicy"
        try:
            func_iam = await client.post(func_iam_url, {})
            for binding in func_iam.get("bindings", []):
                role    = binding.get("role", "")
                members = binding.get("members", [])
                if "allUsers" in members and "invoker" in role:
                    findings.append(Finding(
                        tool=TOOL_NAME, severity="HIGH", type="functions-no-auth",
                        title=f"Cloud Function '{func_short}' sin autenticación (allUsers invoker)",
                        description=(
                            f"La función '{func_short}' tiene el rol '{role}' asignado "
                            f"a 'allUsers'. Cualquier usuario de internet puede invocarla "
                            f"sin autenticación."
                        ),
                        affected=func_name,
                        recommendation=(
                            "Elimina el binding 'allUsers' del rol de invocación. "
                            "Usa Cloud IAM para controlar qué service accounts o usuarios "
                            "pueden invocar la función. Si debe ser pública, añade "
                            "autenticación a nivel de aplicación."
                        ),
                        module="Functions",
                    ))
        except RuntimeError:
            pass

        # 4c. Variables de entorno con posibles secretos embebidos
        env_vars: dict[str, str] = service_cfg.get("environmentVariables", {})
        for var_name, var_value in env_vars.items():
            var_lower = var_name.lower()
            for keyword in SECRET_ENV_KEYWORDS:
                if keyword in var_lower and var_value:
                    # Enmascarar el valor en el hallazgo
                    masked = f"{var_value[:4]}***" if len(var_value) > 4 else "***"
                    findings.append(Finding(
                        tool=TOOL_NAME, severity="HIGH", type="functions-secret-env",
                        title=f"Variable de entorno con posible secreto: {var_name}",
                        description=(
                            f"La función '{func_short}' tiene la variable '{var_name}' "
                            f"con valor '{masked}', lo que sugiere que contiene una "
                            f"credencial o secreto embebido en la configuración de la función."
                        ),
                        affected=f"{func_name} → ENV:{var_name}",
                        recommendation=(
                            "Mueve los secretos a Secret Manager y accede a ellos desde "
                            "la función usando la librería de Secret Manager. Elimina las "
                            "credenciales de las variables de entorno."
                        ),
                        module="Functions",
                        extra={"var_name": var_name},
                    ))
                    break

        # 4d. Función usando SA por defecto de Compute Engine
        service_account = service_cfg.get("serviceAccountEmail", "")
        if service_account and compute_default_sa_pattern.match(service_account):
            findings.append(Finding(
                tool=TOOL_NAME, severity="MEDIUM", type="functions-default-sa",
                title=f"Cloud Function '{func_short}' usa SA por defecto de Compute",
                description=(
                    f"La función '{func_short}' usa la service account de Compute por "
                    f"defecto ({service_account}). Esta SA suele tener permisos amplios "
                    f"(Editor) y es compartida con todas las instancias de Compute del proyecto."
                ),
                affected=func_name,
                recommendation=(
                    "Crea una service account dedicada para cada Cloud Function con "
                    "únicamente los permisos mínimos que la función necesita. "
                    "Evita compartir SAs entre servicios."
                ),
                module="Functions",
                extra={"service_account": service_account},
            ))

    return findings


# ---------------------------------------------------------------------------
# Módulo 5: Auditoría de Reglas de Firewall
# ---------------------------------------------------------------------------

async def audit_firewall(client: GCPClient) -> list[Finding]:
    """
    Audita las reglas de firewall de la red VPC del proyecto GCP.

    Comprobaciones:
      - Reglas 0.0.0.0/0 en puertos sensibles
      - Reglas allow-all desde internet
      - Reglas de internet sin logging habilitado
    """
    findings: list[Finding] = []
    project = client.project_id

    firewalls_url = f"{GCP_COMP_API}/compute/v1/projects/{project}/global/firewalls"
    try:
        firewalls: list[dict] = await client.get_paginated(firewalls_url, "items")
    except RuntimeError as exc:
        findings.append(Finding(
            tool=TOOL_NAME, severity="INFO", type="firewall-error",
            title="No se pudieron listar las reglas de firewall",
            description=str(exc), affected=f"projects/{project}",
            recommendation="Verifica permisos compute.firewalls.list",
            module="Firewall",
        ))
        return findings

    if not firewalls:
        findings.append(Finding(
            tool=TOOL_NAME, severity="INFO", type="firewall-none",
            title="No se encontraron reglas de firewall en el proyecto",
            description="El proyecto no tiene reglas de firewall definidas o no hay acceso.",
            affected=f"projects/{project}",
            recommendation="Verifica la configuración de red del proyecto.",
            module="Firewall",
        ))
        return findings

    for fw in firewalls:
        fw_name      = fw.get("name", "")
        fw_direction = fw.get("direction", "INGRESS")
        fw_disabled  = fw.get("disabled", False)
        source_ranges = fw.get("sourceRanges", [])
        allowed_rules = fw.get("allowed", [])
        log_config   = fw.get("logConfig", {})

        # Solo procesar reglas INGRESS activas
        if fw_direction != "INGRESS" or fw_disabled:
            continue

        # Comprobar si la regla acepta tráfico desde cualquier IP
        is_open_to_internet = "0.0.0.0/0" in source_ranges or "::/0" in source_ranges

        if not is_open_to_internet:
            continue

        # 5a. Detectar allow-all (protocolo 'all') desde internet
        for allow_rule in allowed_rules:
            if allow_rule.get("IPProtocol") == "all":
                findings.append(Finding(
                    tool=TOOL_NAME, severity="CRITICAL", type="firewall-allow-all",
                    title=f"Regla de firewall permite TODO el tráfico desde internet: {fw_name}",
                    description=(
                        f"La regla '{fw_name}' permite todo el tráfico de entrada "
                        f"(IPProtocol=all) desde 0.0.0.0/0. Esto expone completamente "
                        f"todos los servicios en los targets de la regla."
                    ),
                    affected=f"projects/{project}/global/firewalls/{fw_name}",
                    recommendation=(
                        "Elimina esta regla inmediatamente o restringe los rangos de "
                        "origen y los protocolos/puertos al mínimo necesario. "
                        "Implementa una arquitectura de segmentación de red."
                    ),
                    module="Firewall",
                    extra={"source_ranges": source_ranges},
                ))

        # 5b. Detectar puertos sensibles expuestos a internet
        for allow_rule in allowed_rules:
            proto = allow_rule.get("IPProtocol", "")
            ports = allow_rule.get("ports", [])

            if proto == "all":
                # Ya detectado arriba como CRITICAL
                exposed_ports = list(SENSITIVE_PORTS.keys())
            else:
                exposed_ports = []
                for port_spec in ports:
                    # El port_spec puede ser "22", "3306", "3306-3310", etc.
                    port_spec_str = str(port_spec)
                    if "-" in port_spec_str:
                        try:
                            start, end = map(int, port_spec_str.split("-", 1))
                            for sp in SENSITIVE_PORTS:
                                if start <= sp <= end:
                                    exposed_ports.append(sp)
                        except ValueError:
                            pass
                    else:
                        try:
                            pnum = int(port_spec_str)
                            if pnum in SENSITIVE_PORTS:
                                exposed_ports.append(pnum)
                        except ValueError:
                            pass

            for port in exposed_ports:
                service_name = SENSITIVE_PORTS.get(port, str(port))
                severity = "CRITICAL" if port in (22, 3389) else "HIGH"
                findings.append(Finding(
                    tool=TOOL_NAME, severity=severity, type="firewall-sensitive-port",
                    title=f"Puerto {port} ({service_name}) expuesto a internet",
                    description=(
                        f"La regla de firewall '{fw_name}' permite tráfico al puerto "
                        f"{port} ({service_name}) desde 0.0.0.0/0. Esto expone el "
                        f"servicio a ataques de fuerza bruta, exploits y escaneos."
                    ),
                    affected=f"projects/{project}/global/firewalls/{fw_name} → TCP:{port}",
                    recommendation=(
                        f"Restringe el acceso al puerto {port} a rangos de IPs conocidos "
                        f"y de confianza. Usa Cloud IAP para SSH/RDP en lugar de exponer "
                        f"los puertos directamente. Considera usar una VPN."
                    ),
                    module="Firewall",
                    extra={"port": port, "service": service_name, "source_ranges": source_ranges},
                ))

        # 5c. Regla de internet sin logging habilitado
        if is_open_to_internet and not log_config.get("enable", False):
            findings.append(Finding(
                tool=TOOL_NAME, severity="LOW", type="firewall-no-logging",
                title=f"Regla de internet sin logging habilitado: {fw_name}",
                description=(
                    f"La regla '{fw_name}' acepta tráfico desde internet (0.0.0.0/0) "
                    f"pero no tiene Firewall Rules Logging habilitado. Sin logs, no es "
                    f"posible detectar intentos de acceso ni hacer forensia."
                ),
                affected=f"projects/{project}/global/firewalls/{fw_name}",
                recommendation=(
                    "Habilita el logging en la regla de firewall para registrar las "
                    "conexiones aceptadas y denegadas. Los logs fluyen a Cloud Logging "
                    "y pueden analizarse con Log Analytics."
                ),
                module="Firewall",
            ))

    return findings


# ---------------------------------------------------------------------------
# Módulo 6: Riesgos a nivel de Proyecto
# ---------------------------------------------------------------------------

async def audit_project(client: GCPClient) -> list[Finding]:
    """
    Audita riesgos de seguridad a nivel de proyecto GCP.

    Comprobaciones:
      - APIs peligrosas habilitadas (Deployment Manager, Cloud Shell)
      - Audit logging insuficiente
      - Ausencia de org policy contra allUsers en GCS
    """
    findings: list[Finding] = []
    project = client.project_id

    # 6a. Comprobar servicios/APIs habilitados
    services_url = (
        f"{GCP_SVC_API}/v1/projects/{project}/services"
        f"?filter=state:ENABLED"
    )
    try:
        enabled_services: list[dict] = await client.get_paginated(
            services_url, "services"
        )
        enabled_api_names = {
            svc.get("config", {}).get("name", "")
            for svc in enabled_services
        }

        for api_name, info in DANGEROUS_APIS.items():
            if info is None:
                continue  # API necesaria, no alertar
            if api_name in enabled_api_names:
                desc, severity = info
                findings.append(Finding(
                    tool=TOOL_NAME, severity=severity, type="project-dangerous-api",
                    title=f"API potencialmente peligrosa habilitada: {api_name}",
                    description=(
                        f"La API '{api_name}' está habilitada en el proyecto. {desc}"
                    ),
                    affected=f"projects/{project} → {api_name}",
                    recommendation=(
                        f"Si '{api_name}' no se usa activamente, deshabilítala con: "
                        f"gcloud services disable {api_name} --project={project}. "
                        "Revisa regularmente las APIs habilitadas."
                    ),
                    module="Project",
                ))
    except RuntimeError as exc:
        findings.append(Finding(
            tool=TOOL_NAME, severity="INFO", type="project-error",
            title="No se pudieron listar las APIs habilitadas",
            description=str(exc), affected=f"projects/{project}",
            recommendation="Verifica permisos serviceusage.services.list",
            module="Project",
        ))

    # 6b. Comprobar la configuración de Audit Logs
    log_config_url = f"{GCP_CRM_API}/v1/projects/{project}:getIamPolicy"
    try:
        policy = await client.post(log_config_url, {})
        audit_configs: list[dict] = policy.get("auditConfigs", [])

        # Buscar configuración de audit logging para allServices
        all_services_cfg: Optional[dict] = None
        for cfg in audit_configs:
            if cfg.get("service") == "allServices":
                all_services_cfg = cfg
                break

        if not all_services_cfg:
            findings.append(Finding(
                tool=TOOL_NAME, severity="HIGH", type="project-no-audit-log",
                title="Audit Logging no configurado para 'allServices'",
                description=(
                    "El proyecto no tiene Audit Logging configurado para 'allServices'. "
                    "Sin audit logs, las operaciones administrativas, lecturas y escrituras "
                    "de datos no quedan registradas en Cloud Audit Logs."
                ),
                affected=f"projects/{project}",
                recommendation=(
                    "Configura Data Access Audit Logs para 'allServices' habilitando "
                    "ADMIN_READ, DATA_READ y DATA_WRITE. Usa gcloud o la consola de IAM "
                    "en la sección 'Audit Logs'."
                ),
                module="Project",
            ))
        else:
            audit_log_types = {
                alc.get("logType")
                for alc in all_services_cfg.get("auditLogConfigs", [])
            }
            required_types = {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}
            missing = required_types - audit_log_types
            if missing:
                findings.append(Finding(
                    tool=TOOL_NAME, severity="MEDIUM", type="project-incomplete-audit",
                    title=f"Audit Logging incompleto: faltan {', '.join(missing)}",
                    description=(
                        f"El proyecto tiene Audit Logging parcial. Faltan los tipos: "
                        f"{', '.join(missing)}. Sin estos logs no es posible detectar "
                        f"accesos no autorizados a datos o cambios de configuración."
                    ),
                    affected=f"projects/{project} → allServices audit config",
                    recommendation=(
                        "Habilita todos los tipos de Audit Log requeridos: ADMIN_READ, "
                        "DATA_READ y DATA_WRITE. Considera usar la política de Org "
                        "'constraints/gcp.disableCloudLogging' en false para toda la org."
                    ),
                    module="Project",
                    extra={"missing_log_types": list(missing)},
                ))

    except RuntimeError as exc:
        findings.append(Finding(
            tool=TOOL_NAME, severity="INFO", type="project-audit-error",
            title="No se pudo verificar la configuración de Audit Logs",
            description=str(exc), affected=f"projects/{project}",
            recommendation="Verifica permisos para acceder a la política IAM del proyecto",
            module="Project",
        ))

    # 6c. Comprobar Org Policy que bloquee allUsers en GCS
    # Solo disponible si el proyecto pertenece a una organización
    org_policy_url = (
        f"{GCP_ORG_API}/v2/projects/{project}/policies"
        f"?filter=name=constraints%2Fiam.allowedPolicyMemberDomains"
    )
    try:
        org_policies_data = await client.get(org_policy_url)
        policies = org_policies_data.get("policies", [])
        has_domain_restriction = any(
            "allowedPolicyMemberDomains" in p.get("name", "")
            for p in policies
        )
        if not has_domain_restriction:
            findings.append(Finding(
                tool=TOOL_NAME, severity="MEDIUM", type="project-no-org-policy",
                title="Sin Org Policy de restricción de dominios IAM",
                description=(
                    "El proyecto no tiene la constraint 'iam.allowedPolicyMemberDomains' "
                    "configurada. Sin esta política, cualquier usuario puede ser añadido "
                    "a los bindings IAM del proyecto, incluyendo 'allUsers' en GCS."
                ),
                affected=f"projects/{project}",
                recommendation=(
                    "Si el proyecto pertenece a una organización, aplica la Org Policy "
                    "'constraints/iam.allowedPolicyMemberDomains' para restringir los "
                    "dominios permitidos en bindings IAM. Esto previene la exposición "
                    "accidental de recursos a cuentas externas."
                ),
                module="Project",
            ))
    except RuntimeError:
        # Si la API de Org Policy no está disponible (proyecto sin org), es normal
        pass

    return findings


# ---------------------------------------------------------------------------
# GCPAuditor — orquestador de todos los módulos
# ---------------------------------------------------------------------------

class GCPAuditor:
    """
    Orquesta la ejecución de todos los módulos de auditoría GCP de forma asíncrona.
    Agrega los findings y genera el resumen de la auditoría.
    """

    def __init__(self, client: GCPClient) -> None:
        self.client   = client
        self.findings: list[Finding] = []
        self._start_time: Optional[datetime] = None
        self._end_time:   Optional[datetime] = None

    async def run(self) -> list[Finding]:
        """Ejecuta todos los módulos de auditoría en paralelo."""
        self._start_time = datetime.now(tz=timezone.utc)

        console.print()
        console.print(Panel(
            f"[bold cyan]Proyecto:[/bold cyan] [white]{self.client.project_id}[/white]\n"
            f"[bold cyan]Inicio:  [/bold cyan] [white]{self._start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}[/white]",
            title="[bold green]VampSecure Labs · GCP Audit[/bold green]",
            border_style="green",
        ))
        console.print()

        modules = [
            ("IAM & Service Accounts", audit_iam),
            ("GCS Bucket Security",    audit_gcs),
            ("GKE Cluster Security",   audit_gke),
            ("Cloud Functions",        audit_functions),
            ("Firewall Rules",         audit_firewall),
            ("Project-Level Risks",    audit_project),
        ]

        # Ejecutar todos los módulos en paralelo
        tasks = {name: asyncio.create_task(fn(self.client)) for name, fn in modules}

        for mod_name, task in tasks.items():
            console.print(f"  [dim]→ Auditando:[/dim] [bold]{mod_name}[/bold]...")
            try:
                mod_findings = await task
                self.findings.extend(mod_findings)
                count_by_sev = {}
                for f in mod_findings:
                    count_by_sev[f.severity] = count_by_sev.get(f.severity, 0) + 1
                sev_str = "  ".join(
                    f"[{SEVERITY_COLOR.get(s, 'white')}]{s}: {c}[/]"
                    for s, c in sorted(count_by_sev.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99))
                ) or "[green]Sin hallazgos[/green]"
                console.print(f"    [green]✓[/green] {mod_name} — {sev_str}")
            except Exception as exc:
                console.print(f"    [red]✗ Error en {mod_name}: {exc}[/red]")

        self._end_time = datetime.now(tz=timezone.utc)

        # Ordenar findings por severidad
        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        return self.findings

    def print_summary(self) -> None:
        """Imprime la tabla resumen de hallazgos en consola."""
        if not self.findings:
            console.print(
                Panel("[bold green]No se detectaron hallazgos de seguridad.[/bold green]",
                      border_style="green")
            )
            return

        table = Table(
            title=f"[bold]Resumen de Hallazgos — {self.client.project_id}[/bold]",
            show_header=True, header_style="bold white",
            border_style="bright_black",
        )
        table.add_column("Sev",          width=10, style="bold")
        table.add_column("Módulo",       width=16)
        table.add_column("Tipo",         width=28)
        table.add_column("Título",       width=55)
        table.add_column("Afectado",     width=45)

        for f in self.findings:
            sev_style = SEVERITY_COLOR.get(f.severity, "white")
            table.add_row(
                Text(f.severity, style=sev_style),
                f.module,
                f.type,
                f.title[:55],
                f.affected[:45],
            )

        console.print(table)
        console.print()

        # Conteo por severidad
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        summary_parts = [
            f"[{SEVERITY_COLOR.get(s, 'white')}]{s}: {c}[/]"
            for s, c in sorted(counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99))
        ]
        duration = (
            (self._end_time - self._start_time).total_seconds()
            if self._end_time and self._start_time else 0
        )
        console.print(
            f"  [bold]Total:[/bold] [white]{len(self.findings)} hallazgos[/white]  "
            + "  ".join(summary_parts)
            + f"  [dim]({duration:.1f}s)[/dim]"
        )
        console.print()

    def has_critical_or_high(self) -> bool:
        """Devuelve True si hay hallazgos de severidad CRITICAL o HIGH."""
        return any(f.severity in ("CRITICAL", "HIGH") for f in self.findings)


# ---------------------------------------------------------------------------
# VampSecReport — generador de informes JSON y HTML
# ---------------------------------------------------------------------------

class VampSecReport:
    """
    Genera los informes de auditoría en formato JSON y HTML dark-theme.
    """

    def __init__(self, auditor: GCPAuditor) -> None:
        self.auditor  = auditor
        self.findings = auditor.findings
        self.project  = auditor.client.project_id

    def _build_metadata(self) -> dict:
        """Construye el bloque de metadatos del informe."""
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        return {
            "tool":       TOOL_NAME,
            "version":    VERSION,
            "project":    self.project,
            "timestamp":  datetime.now(tz=timezone.utc).isoformat(),
            "total":      len(self.findings),
            "by_severity": counts,
        }

    def write_json(self, output_path: str) -> None:
        """Escribe el informe completo en formato JSON."""
        report = {
            "metadata": self._build_metadata(),
            "findings": [f.to_dict() for f in self.findings],
        }
        path = Path(output_path)
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"  [green]→ JSON guardado:[/green] {path.resolve()}")

    def write_html(self, output_path: str) -> None:
        """Genera un informe HTML dark-theme standalone con todos los hallazgos."""
        meta = self._build_metadata()
        sev_colors = {
            "CRITICAL": "#ff4444",
            "HIGH":     "#ff8800",
            "MEDIUM":   "#ffcc00",
            "LOW":      "#44aaff",
            "INFO":     "#44ff88",
        }

        # Generar filas de la tabla
        rows_html = ""
        for f in self.findings:
            color   = sev_colors.get(f.severity, "#ffffff")
            title   = escape(f.title)
            desc    = escape(f.description)
            rec     = escape(f.recommendation)
            aff     = escape(f.affected)
            mod     = escape(f.module)
            ftype   = escape(f.type)
            rows_html += f"""
            <tr>
                <td><span class="badge" style="background:{color}22;color:{color};border:1px solid {color}40">{f.severity}</span></td>
                <td class="mono">{mod}</td>
                <td class="mono">{ftype}</td>
                <td>
                    <strong>{title}</strong><br>
                    <small class="desc">{desc}</small><br>
                    <span class="rec">▶ {rec}</span>
                </td>
                <td class="mono small">{aff}</td>
            </tr>"""

        # Contadores de severidad para el resumen
        counts_html = ""
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            c     = meta["by_severity"].get(sev, 0)
            color = sev_colors.get(sev, "#fff")
            counts_html += (
                f'<div class="stat-card" style="border-left:4px solid {color}">'
                f'<div class="stat-num" style="color:{color}">{c}</div>'
                f'<div class="stat-label">{sev}</div></div>\n'
            )

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GCP Audit — {escape(self.project)} — VampSecure Labs</title>
<style>
  :root {{
    --bg:        #0d1117;
    --bg2:       #161b22;
    --bg3:       #21262d;
    --border:    #30363d;
    --text:      #c9d1d9;
    --text-dim:  #8b949e;
    --accent:    #58a6ff;
    --green:     #3fb950;
    --red:       #ff4444;
  }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif;
         font-size:14px; line-height:1.5; padding:2rem; }}
  h1 {{ color:var(--accent); font-size:1.6rem; margin-bottom:.25rem; }}
  h2 {{ color:var(--text-dim); font-size:1rem; font-weight:400; margin-bottom:1.5rem; }}
  .header {{ border-bottom:1px solid var(--border); padding-bottom:1.5rem; margin-bottom:1.5rem; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:4px;
            font-size:.75rem; font-weight:700; letter-spacing:.05em; }}
  .stats {{ display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:2rem; }}
  .stat-card {{ background:var(--bg2); border-radius:6px; padding:.75rem 1.2rem;
                min-width:90px; border-left:4px solid var(--border); }}
  .stat-num {{ font-size:2rem; font-weight:700; line-height:1; }}
  .stat-label {{ font-size:.7rem; color:var(--text-dim); text-transform:uppercase;
                 letter-spacing:.1em; margin-top:.25rem; }}
  .meta {{ display:flex; gap:2rem; margin-bottom:2rem; flex-wrap:wrap; }}
  .meta-item {{ background:var(--bg2); border:1px solid var(--border); border-radius:6px;
                padding:.5rem 1rem; }}
  .meta-item label {{ font-size:.7rem; color:var(--text-dim); display:block;
                      text-transform:uppercase; letter-spacing:.05em; }}
  .meta-item span {{ font-size:.9rem; font-weight:600; color:var(--accent); }}
  table {{ width:100%; border-collapse:collapse; background:var(--bg2);
           border-radius:8px; overflow:hidden; border:1px solid var(--border); }}
  th {{ background:var(--bg3); color:var(--text-dim); text-align:left; padding:.6rem 1rem;
        font-size:.75rem; text-transform:uppercase; letter-spacing:.05em; border-bottom:1px solid var(--border); }}
  td {{ padding:.6rem 1rem; border-bottom:1px solid var(--border); vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
  tr:hover td {{ background:var(--bg3); }}
  .mono {{ font-family:'Courier New',monospace; font-size:.8rem; }}
  .small {{ font-size:.75rem; }}
  .desc {{ color:var(--text-dim); }}
  .rec {{ color:var(--green); font-size:.8rem; }}
  footer {{ margin-top:2rem; text-align:center; color:var(--text-dim); font-size:.75rem; }}
  .brand {{ color:var(--accent); font-weight:700; }}
</style>
</head>
<body>
<div class="header">
  <h1>🔐 GCP Security Audit Report</h1>
  <h2>VampSecure Labs · VampSecure Studios</h2>
</div>
<div class="meta">
  <div class="meta-item"><label>Proyecto</label><span>{escape(self.project)}</span></div>
  <div class="meta-item"><label>Herramienta</label><span>{TOOL_NAME} v{VERSION}</span></div>
  <div class="meta-item"><label>Fecha</label><span>{meta['timestamp'][:19].replace('T',' ')} UTC</span></div>
  <div class="meta-item"><label>Total hallazgos</label><span>{meta['total']}</span></div>
</div>
<div class="stats">
{counts_html}
</div>
<table>
  <thead>
    <tr>
      <th style="width:100px">Severidad</th>
      <th style="width:100px">Módulo</th>
      <th style="width:180px">Tipo</th>
      <th>Hallazgo</th>
      <th style="width:220px">Recurso afectado</th>
    </tr>
  </thead>
  <tbody>
{rows_html}
  </tbody>
</table>
<footer>
  <p>Generado por <span class="brand">VampSecure Labs</span> —
     {TOOL_NAME} v{VERSION} · © VampSecure Studios. Uso exclusivo en auditorías autorizadas.</p>
</footer>
</body>
</html>"""

        path = Path(output_path)
        path.write_text(html, encoding="utf-8")
        console.print(f"  [green]→ HTML guardado:[/green] {path.resolve()}")


# ---------------------------------------------------------------------------
# Punto de entrada — main()
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """Construye y devuelve el parser de argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "VampSecure Labs · Auditor de seguridad GCP\n"
            "Detecta misconfiguraciones en IAM, GCS, GKE, Cloud Functions, Firewall y Proyecto."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            f"  {TOOL_NAME} --project my-project-id\n"
            f"  {TOOL_NAME} --project my-project-id --credentials sa-key.json\n"
            f"  {TOOL_NAME} --project my-project-id --json findings.json --html report.html\n"
        ),
    )
    parser.add_argument(
        "--project", "-p",
        required=True,
        metavar="PROJECT_ID",
        help="ID del proyecto GCP a auditar (obligatorio)",
    )
    parser.add_argument(
        "--credentials", "-c",
        metavar="FICHERO_JSON",
        default=None,
        help="Ruta al fichero JSON de service account. Si se omite, usa gcloud ADC.",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        default=None,
        help="Ruta del fichero de salida JSON con los hallazgos",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        default=None,
        help="Ruta del fichero de salida HTML (informe dark-theme)",
    )
    parser.add_argument(
        "--modules", "-m",
        nargs="+",
        choices=["iam", "gcs", "gke", "functions", "firewall", "project"],
        default=None,
        help="Ejecutar solo los módulos especificados (por defecto: todos)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Silenciar la tabla resumen en consola (solo errores críticos)",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"{TOOL_NAME} v{VERSION} · VampSecure Labs",
    )
    return parser


async def _main_async(args: argparse.Namespace) -> int:
    """
    Función principal asíncrona. Autentifica, ejecuta la auditoría y genera los informes.
    Devuelve el exit code apropiado (0, 1 o 2).
    """
    # Verificar que el fichero de credenciales existe si se especificó
    if args.credentials and not Path(args.credentials).exists():
        console.print(f"[bold red]Error:[/bold red] El fichero de credenciales no existe: {args.credentials}")
        return 2

    client = GCPClient(
        project_id=args.project,
        credentials_file=args.credentials,
    )

    try:
        console.print(f"  [dim]Autenticando con GCP...[/dim]")
        await client.authenticate()
        console.print(f"  [green]✓[/green] Autenticación correcta")
    except RuntimeError as exc:
        console.print(f"[bold red]Error de autenticación:[/bold red] {exc}")
        await client.close()
        return 2
    except Exception as exc:
        console.print(f"[bold red]Error inesperado en autenticación:[/bold red] {exc}")
        await client.close()
        return 2

    try:
        auditor = GCPAuditor(client)

        # Si se especificaron módulos concretos, parchear los módulos disponibles
        if args.modules:
            mod_map = {
                "iam":       audit_iam,
                "gcs":       audit_gcs,
                "gke":       audit_gke,
                "functions": audit_functions,
                "firewall":  audit_firewall,
                "project":   audit_project,
            }
            # Ejecutar solo los módulos seleccionados
            findings: list[Finding] = []
            for mod_name in args.modules:
                console.print(f"  [dim]→ Auditando módulo:[/dim] [bold]{mod_name}[/bold]...")
                try:
                    mod_findings = await mod_map[mod_name](client)
                    findings.extend(mod_findings)
                    console.print(f"    [green]✓[/green] {mod_name}: {len(mod_findings)} hallazgos")
                except Exception as exc:
                    console.print(f"    [red]✗ Error en {mod_name}: {exc}[/red]")
            auditor.findings = sorted(
                findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
            )
            auditor._start_time = datetime.now(tz=timezone.utc)
            auditor._end_time   = datetime.now(tz=timezone.utc)
        else:
            await auditor.run()

        if not args.quiet:
            auditor.print_summary()

        # Generar informes
        if args.json or args.html:
            console.print("[bold]Generando informes...[/bold]")
            reporter = VampSecReport(auditor)
            if args.json:
                reporter.write_json(args.json)
            if args.html:
                reporter.write_html(args.html)
            console.print()

        return 1 if auditor.has_critical_or_high() else 0

    except KeyboardInterrupt:
        console.print("\n[yellow]Auditoría interrumpida por el usuario.[/yellow]")
        return 2
    except Exception as exc:
        console.print(f"[bold red]Error durante la auditoría:[/bold red] {exc}")
        return 2
    finally:
        await client.close()


def main() -> None:
    """Punto de entrada principal. Imprime el banner y lanza el bucle asyncio."""
    console.print(BANNER, highlight=False)

    parser = build_arg_parser()
    args   = parser.parse_args()

    exit_code = asyncio.run(_main_async(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
