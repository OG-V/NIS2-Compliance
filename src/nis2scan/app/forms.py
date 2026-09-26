"""What the app asks for, per kind of system, in a consultant's words.

Each field maps onto a field of the target model in nis2scan.config. A field listing
`products` is shown only for those products. Credentials (`secret`) are typed into a
password box and stored in secrets.env; target.yaml keeps only the variable name, in
the model's `<field>_env` attribute.
"""

from __future__ import annotations

from nis2scan.adapters.backup import ADAPTERS as BACKUP
from nis2scan.adapters.identity import ADAPTERS as IDENTITY
from nis2scan.adapters.logging import ADAPTERS as LOGGING


def _products(adapters) -> list[dict]:
    return [{"value": "auto", "label": "Detect automatically"}] + [
        {"value": key, "label": adapter.label} for key, adapter in sorted(adapters.items())
    ]


def F(key, label, kind="text", **extra) -> dict:
    return {"key": key, "label": label, "kind": kind, **extra}


NAME = F("name", "Name in the report", placeholder="e.g. customer-portal", required=True)

SECTIONS = [
    {
        "key": "web",
        "label": "Web endpoints",
        "icon": "globe",
        "blurb": "Public or internal websites and APIs. The scanner checks TLS versions, "
        "certificates and security headers.",
        "fields": [
            NAME,
            F("host", "Host name or IP address", required=True, placeholder="portal.example.com"),
            F("https_port", "HTTPS port", "number", default=443, required=True),
            F("http_port", "HTTP port", "number", default=80, required=True),
        ],
    },
    {
        "key": "ssh",
        "label": "Servers (SSH)",
        "icon": "server",
        "blurb": "Linux servers reachable over SSH. The scanner reads the SSH configuration "
        "the server offers; nothing is changed.",
        "fields": [
            NAME,
            F("host", "Host name or IP address", required=True),
            F("port", "SSH port", "number", default=22, required=True),
            F(
                "container",
                "Docker container (optional)",
                help="Lets the scanner read the effective sshd configuration. Without it, "
                "only network-visible checks run.",
                advanced=True,
            ),
        ],
    },
    {
        "key": "idp",
        "label": "Identity provider",
        "icon": "key",
        "blurb": "Where staff sign in. The scanner reads MFA, password and lockout policies "
        "with a read-only administrator credential.",
        "products": _products(IDENTITY),
        "fields": [
            NAME,
            F(
                "url",
                "Sign-in or admin URL",
                required=True,
                placeholder="https://login.example.com",
                help="Keycloak: the server URL. Okta: https://<org>.okta.com. "
                "Entra ID: https://login.microsoftonline.com/<tenant ID>.",
            ),
            F("realm", "Realm", products=["keycloak"], required=True),
            F("admin_user", "Admin user name", products=["keycloak"], required=True),
            F("admin_password_env", "Admin password", "secret", products=["keycloak"]),
            F(
                "api_token_env",
                "API token (read-only admin)",
                "secret",
                products=["okta"],
                help="Created under Security › API › Tokens by a read-only administrator.",
            ),
            F("client_id", "Application (client) ID", products=["entra-id"], required=True),
            F("client_secret_env", "Client secret", "secret", products=["entra-id"]),
        ],
    },
    {
        "key": "logs",
        "label": "Log store",
        "icon": "logs",
        "blurb": "Central logging or SIEM. The scanner checks how long logs are kept.",
        "products": _products(LOGGING),
        "fields": [
            NAME,
            F(
                "url",
                "URL",
                placeholder="https://logs.example.com:9200",
                products=["auto", "loki", "elasticsearch", "splunk"],
                required=True,
            ),
            F("username", "User name", products=["elasticsearch", "splunk"]),
            F("password_env", "Password", "secret", products=["elasticsearch", "splunk"]),
            F(
                "api_key_env",
                "API key (instead of a password)",
                "secret",
                products=["elasticsearch"],
            ),
            F("token_env", "Token (instead of a password)", "secret", products=["splunk"]),
            F(
                "indices",
                "Indices holding logs",
                default="*",
                products=["elasticsearch", "splunk"],
                advanced=True,
            ),
            F(
                "tls_fingerprint",
                "Pinned certificate (SHA-256)",
                products=["elasticsearch", "splunk"],
                help="For a server with a self-signed certificate.",
                advanced=True,
            ),
            F("subscription", "Azure subscription ID", products=["sentinel"], required=True),
            F("workspace", "Log Analytics workspace (optional)", products=["sentinel"]),
            F("tenant", "Tenant ID", products=["sentinel"], required=True),
            F("client_id", "Application (client) ID", products=["sentinel"], required=True),
            F("client_secret_env", "Client secret", "secret", products=["sentinel"]),
        ],
    },
    {
        "key": "backup",
        "label": "Backups",
        "icon": "archive",
        "blurb": "Backup repositories or services. The scanner checks that backups are recent "
        "and encrypted.",
        "products": _products(BACKUP),
        "fields": [
            NAME,
            F(
                "container",
                "Docker container running the backup tool",
                products=["auto", "restic", "borg"],
                help="Or give the repository and its password below.",
            ),
            F("repository", "Repository", products=["restic", "borg"]),
            F("password_env", "Repository password", "secret", products=["restic", "borg"]),
            F("url", "Backup server API URL", products=["veeam"], required=True),
            F("username", "User name", products=["veeam"], required=True),
            F("password_env", "Password", "secret", products=["veeam"]),
            F("tls_fingerprint", "Pinned certificate (SHA-256)", products=["veeam"], advanced=True),
            F("region", "AWS region", products=["aws-backup"], required=True),
            F("aws_profile", "AWS CLI profile (optional)", products=["aws-backup"]),
            F("access_key_id_env", "Access key ID", "secret", products=["aws-backup"]),
            F("secret_access_key_env", "Secret access key", "secret", products=["aws-backup"]),
            F("subscription", "Azure subscription ID", products=["azure-backup"], required=True),
            F("tenant", "Tenant ID", products=["azure-backup"], required=True),
            F("client_id", "Application (client) ID", products=["azure-backup"], required=True),
            F("client_secret_env", "Client secret", "secret", products=["azure-backup"]),
        ],
    },
    {
        "key": "docker",
        "label": "Container workloads",
        "icon": "box",
        "blurb": "Docker Compose projects. The scanner checks their images for known "
        "vulnerabilities.",
        "fields": [NAME, F("compose_project", "Compose project name", required=True)],
    },
]

DOCUMENTS = [
    F("dir", "Documents folder", "folder", required=True),
    F("ir_plan", "Incident response plan", "file", required=True),
    F("asset_inventory", "Asset inventory", "file", required=True),
    F(
        "risk_exceptions",
        "Risk exception register (optional)",
        "file",
        help="Vulnerabilities the client has formally accepted.",
    ),
    F(
        "evidence_register",
        "Evidence register (optional)",
        "file",
        help="Your document reviews. The app can start one for you.",
    ),
]

ENGAGEMENT = [
    F("client", "Client", required=True, placeholder="Legal name of the organisation"),
    F(
        "authorised_by",
        "Authorised by",
        required=True,
        placeholder="Name and role, e.g. Jane Smith, CIO",
        help="The person at the client who authorised the scan in writing.",
    ),
    F("authorised_on", "Authorised on", "date", required=True),
    F("valid_until", "Valid until", "date", required=True),
    F(
        "active_tests",
        "Allow active tests",
        "bool",
        help="Active tests go beyond reading, e.g. trying a default admin password once. "
        "They can trigger the client's alerts, so only allow them if agreed.",
    ),
    F("notes", "Notes (optional)", "textarea"),
]


def schema() -> dict:
    return {"sections": SECTIONS, "documents": DOCUMENTS, "engagement": ENGAGEMENT}
