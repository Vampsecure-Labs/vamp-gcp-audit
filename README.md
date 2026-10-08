<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->

  <img src="https://github.com/Vampsecure-Labs/vamp-gcp-audit/actions/workflows/ci.yml/badge.svg" alt="CI"/>
# vamp-gcp-audit

**VampSecure Labs · VampSecure Studios**

Auditor de seguridad no-destructivo para entornos Google Cloud Platform. Detecta misconfiguraciones
críticas en IAM, GCS, GKE, Cloud Functions, Firewall y configuración de proyecto usando únicamente
la API REST de GCP (sin SDKs de `google-cloud-*`).

---

## Instalación


```bash
pip install vamp-gcp-audit
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-gcp-audit
```

```bash
pip install -r requirements.txt
```

> `cryptography` solo es necesaria si usas `--credentials` con un fichero JSON de service account.

---

## Uso

```bash
# Con credenciales de gcloud ADC (gcloud auth application-default login)
python vamp_gcp_audit.py --project my-project-id

# Con fichero de service account
python vamp_gcp_audit.py --project my-project-id --credentials sa-key.json

# Guardar informe JSON y HTML
python vamp_gcp_audit.py --project my-project-id --json findings.json --html report.html

# Ejecutar solo módulos concretos
python vamp_gcp_audit.py --project my-project-id --modules iam firewall

# Modo silencioso (sin tabla resumen en consola)
python vamp_gcp_audit.py --project my-project-id --quiet --json out.json
```

---

## Módulos de auditoría

| Módulo          | Descripción                                                |
|-----------------|------------------------------------------------------------|
| `iam`           | Service accounts con roles excesivos, keys antiguas        |
| `gcs`           | Buckets públicos, ACLs legacy, logging/versioning          |
| `gke`           | RBAC legacy, auth estática, Network Policy, endpoints      |
| `functions`     | HTTPS, autenticación, secretos en env vars, SA por defecto |
| `firewall`      | Puertos sensibles expuestos, allow-all, logging            |
| `project`       | APIs peligrosas, audit logging, org policy                 |

---

## Permisos GCP necesarios

La cuenta o service account usada necesita los siguientes roles mínimos de solo lectura:

- `roles/viewer` (base)
- `roles/iam.securityReviewer`
- `roles/container.viewer`
- `roles/cloudfunctions.viewer`

---

## Exit codes

| Código | Significado                              |
|--------|------------------------------------------|
| `0`    | Sin hallazgos CRITICAL ni HIGH           |
| `1`    | Se encontraron hallazgos CRITICAL o HIGH |
| `2`    | Error de autenticación o ejecución       |

---

## Autenticación

### gcloud ADC (recomendado para uso local)

```bash
gcloud auth application-default login
python vamp_gcp_audit.py --project PROJECT_ID
```

### Service Account JSON

```bash
python vamp_gcp_audit.py --project PROJECT_ID --credentials /ruta/a/sa-key.json
```

---

## Sample Output

```text
vamp-gcp-audit v1.2 · project: my-prod-project
─────────────────────────────────────────────────────────────────────────
[CRITICAL] IAM-003  Service account key age > 90 days
           sa: api-backend@my-prod-project.iam.gserviceaccount.com
           key_id: a1b2c3d4e5  created: 2026-06-10
[CRITICAL] GKE-002  Static basic authentication enabled on cluster
           cluster: prod-cluster  region: europe-west1
[HIGH]     GCS-001  Bucket publicly accessible via allUsers IAM binding
           bucket: my-prod-project-assets
           binding: allUsers → roles/storage.objectViewer
[HIGH]     GKE-004  Master authorized networks not configured
           cluster: prod-cluster  endpoint public, unrestricted
[HIGH]     GCS-002  Access logging disabled on bucket: my-prod-backups
[MEDIUM]   FW-001   Firewall rule allow-ssh: port 22 open to 0.0.0.0/0
[MEDIUM]   PROJECT-001  Cloud Audit Logging not enabled for storage.googleapis.com
[LOW]      GCS-003  Object versioning not enabled: my-prod-assets

┌──────────────┬──────┬──────┬────────┬──────┬──────────────┐
│ Módulo       │ Chks │ Pass │  Fail  │ Skip │ Hallazgos    │
├──────────────┼──────┼──────┼────────┼──────┼──────────────┤
│ iam          │  12  │   9  │   2    │   1  │ 1C 1H        │
│ gcs          │   9  │   5  │   3    │   1  │ 1H 1M 1L     │
│ gke          │  11  │   8  │   2    │   1  │ 1C 1H        │
│ firewall     │   8  │   6  │   1    │   1  │ 1M           │
│ project      │   6  │   4  │   1    │   1  │ 1M           │
└──────────────┴──────┴──────┴────────┴──────┴──────────────┘
2 CRITICAL · 3 HIGH · 2 MEDIUM · 1 LOW   exit 1
```

---

## Why vamp-gcp-audit vs. Forseti Security · ScoutSuite · CloudSploit

| Característica | vamp-gcp-audit | Forseti Security | ScoutSuite | CloudSploit |
|---|---|---|---|---|
| Sin SDK `google-cloud-*` | ✅ solo API REST | ❌ requiere SDK | ❌ requiere SDK | ✅ |
| Salida HTML autónoma dark-theme | ✅ | ❌ solo dashboard web | ✅ | ❌ |
| Sin infraestructura propia | ✅ cero deps extra | ❌ Kubernetes + Cloud SQL | ✅ | ✅ |
| Módulo GKE (RBAC, auth, NetworkPolicy) | ✅ | ✅ | ⚠️ parcial | ⚠️ parcial |
| Módulo Cloud Functions (env secrets, SA) | ✅ | ❌ | ⚠️ parcial | ✅ |
| Exit codes CI/CD 0/1/2 | ✅ | ❌ | ✅ | ✅ |
| Integración toolkit VSL (JSON unificado) | ✅ | ❌ | ❌ | ❌ |

- **Sin SDK propietario**: solo `urllib` + REST directa; sin conflictos de versión ni cadena de 20 paquetes `google-cloud-*`.
- **Instalación mínima**: `pip install vamp-gcp-audit` funciona desde cero en cualquier runner de CI.
- **Sin infraestructura propia**: Forseti exige desplegar su propio servidor en GKE más Cloud SQL; aquí no hay estado ni base de datos.
- **Parte del toolkit unificado VSL**: los hallazgos JSON son consumibles por `vamp-orchestrator` junto con los de todos los demás módulos.

---

## Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| IAM-001 | Service account with editor/owner role at project level | CIS GCP Benchmark v2.0 §1.5 | HIGH |
| IAM-002 | Service account with org-level IAM binding | CIS GCP v2.0 §1.6 | HIGH |
| IAM-003 | Service account key older than 90 days | CIS GCP v2.0 §1.7 / NIST CSF PR.AC-1 | CRITICAL |
| IAM-004 | User-managed service account key present | CIS GCP v2.0 §1.7 | MEDIUM |
| GCS-001 | Bucket accessible by allUsers or allAuthenticatedUsers | CIS GCP v2.0 §5.1 / NIST CSF PR.DS-5 | CRITICAL |
| GCS-002 | Access logging disabled on storage bucket | CIS GCP v2.0 §5.3 / NIST CSF DE.AE-3 | HIGH |
| GCS-003 | Object versioning disabled on bucket | CIS GCP v2.0 §5.4 | MEDIUM |
| GKE-001 | Legacy ABAC authorization enabled on cluster | CIS GCP v2.0 §7.5 | CRITICAL |
| GKE-002 | Basic authentication enabled on GKE master | CIS GCP v2.0 §7.1 / NIST CSF PR.AC-1 | CRITICAL |
| GKE-003 | Network Policy not enabled on cluster | CIS GCP v2.0 §7.11 | HIGH |
| GKE-004 | Master authorized networks not configured | CIS GCP v2.0 §7.4 / NIST CSF PR.AC-5 | HIGH |
| FW-001 | Firewall rule allows SSH (22) from 0.0.0.0/0 | CIS GCP v2.0 §3.6 | CRITICAL |
| FW-002 | Firewall rule allows RDP (3389) from 0.0.0.0/0 | CIS GCP v2.0 §3.7 | CRITICAL |
| PROJECT-001 | Cloud Audit Logging not enabled for all services | CIS GCP v2.0 §2.1 / NIST CSF DE.AE-3 | MEDIUM |
| SQL-001 | Cloud SQL instance publicly accessible | CIS GCP v2.0 §6.2 / NIST CSF PR.DS-5 | HIGH |
| SQL-002 | Cloud SQL without SSL/TLS enforcement | CIS GCP v2.0 §6.4 | HIGH |

---

© VampSecure Studios — VampSecure Labs Security Research Division.
Uso exclusivo en entornos autorizados.

---

## Versión
v1.2 — VampSecure Labs Security Research Division
