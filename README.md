# vamp-gcp-audit

**VampSecure Labs · VampSecure Studios**

Auditor de seguridad no-destructivo para entornos Google Cloud Platform. Detecta misconfiguraciones
críticas en IAM, GCS, GKE, Cloud Functions, Firewall y configuración de proyecto usando únicamente
la API REST de GCP (sin SDKs de `google-cloud-*`).

---

## Instalación

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

© VampSecure Studios — VampSecure Labs Security Research Division.
Uso exclusivo en entornos autorizados.
