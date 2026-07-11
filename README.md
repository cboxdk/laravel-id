# cboxdk/laravel-id

**Cbox ID** — the self-hostable, Laravel-native identity platform (framework layer).

One package, clean internal module boundaries under `Cbox\Id\*`:
`Kernel\{Tenancy,Crypto,Audit,Events,Authorization}` · `Organization` · `Identity` ·
`Federation` (SAML/OIDC SP) · `Directory` (SCIM) · `OAuthServer` · `AccessControl`
(RBAC + billing-fed entitlements) · `AuditQuery` · `Webhooks` · `Api`.

Owned logic, MIT-licensed. UI/admin is a separate (later, likely closed) layer.
Built against the locked foundation contracts. Split a module into its own package only
when a boundary earns it.

> Private during internal dogfooding.
