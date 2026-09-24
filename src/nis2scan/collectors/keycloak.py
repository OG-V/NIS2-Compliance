"""Keycloak identity provider: realm security settings and users' MFA state."""

import json
import urllib.error
import urllib.parse
import urllib.request

from nis2scan.registry import CollectorError, Context, collector

DEFAULT_ADMIN = ("admin", "admin")


def _token(base_url: str, username: str, password: str) -> tuple[int, str | None]:
    data = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": username,
            "password": password,
        }
    ).encode()
    url = f"{base_url}/realms/master/protocol/openid-connect/token"
    try:
        with urllib.request.urlopen(url, data=data, timeout=10) as resp:
            return resp.status, json.load(resp)["access_token"]
    except urllib.error.HTTPError as exc:
        return exc.code, None


def _get(base_url: str, token: str, path: str):
    req = urllib.request.Request(
        f"{base_url}/admin/realms/{path}", headers={"Authorization": f"Bearer {token}"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.load(resp)


@collector("keycloak_realm", requires="idp")
def keycloak_realm(ctx: Context) -> dict:
    idp = ctx.target.idp
    status, token = _token(idp.url, idp.admin_user, ctx.target.secret(idp.admin_password_env))
    if not token:
        raise CollectorError(f"admin login to {idp.url} failed with HTTP {status}")

    realm = _get(idp.url, token, idp.realm)
    actions = _get(idp.url, token, f"{idp.realm}/authentication/required-actions")
    users = []
    for user in _get(idp.url, token, f"{idp.realm}/users?max=1000"):
        creds = _get(idp.url, token, f"{idp.realm}/users/{user['id']}/credentials")
        users.append(
            {
                "username": user["username"],
                "enabled": user["enabled"],
                "required_actions": user.get("requiredActions", []),
                "credential_types": sorted({c["type"] for c in creds}),
            }
        )
    return {
        "realm": idp.realm,
        "settings": {
            key: realm.get(key)
            for key in ("bruteForceProtected", "failureFactor", "passwordPolicy", "otpPolicyType")
        },
        "required_actions": [
            {k: a[k] for k in ("alias", "enabled", "defaultAction")} for a in actions
        ],
        "users": users,
    }


@collector("keycloak_default_admin", requires="idp")
def keycloak_default_admin(ctx: Context) -> dict:
    """Try the documented default admin credentials once. One attempt cannot trigger lockout."""
    status, token = _token(ctx.target.idp.url, *DEFAULT_ADMIN)
    return {
        "username_tried": DEFAULT_ADMIN[0],
        "http_status": status,
        "accepted": token is not None,
    }
