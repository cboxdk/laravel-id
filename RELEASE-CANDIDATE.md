# laravel-id 2.0.0

Status: prepared local candidate. No public tag, registry publication or deployment has occurred.

Stage role changes for explicit activation; record invitation acceptance subjects; restrict resource introspection; make role grants, revocations, directory reconciliation and manual promotion atomic.

## Upgrade requirements

Run all framework migrations before the matching app rollout, including role_grant_subject_locks; drain old workers. Custom Invitations implementations must accept optional clientId. Existing role holders change permissions only after explicit definition activation. See UPGRADING.md for lock ordering and source promotion.

Dependency installation against public registries remains contingent on the approved release cascade. Local artifact checks prove the enclosed contents only; they do not claim public indexing.
