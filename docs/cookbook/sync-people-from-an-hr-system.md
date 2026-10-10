---
title: Sync people from an HR system
weight: 47
description: Connect Workday, BambooHR, Rippling, HiBob or Personio as a directory — joiners get accounts on their start date, leavers lose them at the end of their last day, departments become groups
---

# Sync people from an HR system

An HR system is the source of truth for who works at a company. Connected as a directory,
it provisions an account when somebody starts, keeps their name, title, department and
manager current, and deactivates the account — revoking every session — when they leave.

It is a **pull** directory, like Google Workspace and Microsoft Entra: the platform fetches
from the HR system's API on a schedule. Nothing is pushed to us, so nothing on the HR
side needs a SCIM endpoint.

| HR system | What the customer creates | Incremental |
|---|---|---|
| Workday | A custom report enabled as a web service (RaaS), shared with an integration system user — or an API client with a refresh token | No — every run is full |
| BambooHR | An API key for a user who can see every employee | Yes (`/employees/changed`) |
| Rippling | An API token with `workers.read`, `users.read`, `departments.read` | Yes (`updated_at` filter) |
| HiBob | An API service user that can read root, work and lifecycle fields of everybody | No |
| Personio | API credentials (v2) with persons and org-units read access | No |

## 1. Collect and check the credentials

`HrisCatalog` holds each system's setup steps, its documentation link, and the credentials
its connector reads — so a form built from it collects exactly those.

```php
use Cbox\Id\Directory\DirectoryConnectors;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\Exceptions\IncompleteHrisCredentials;
use Cbox\Id\Directory\Hris\HrisCatalog;

$provider = DirectoryProvider::BambooHr;

$setup = HrisCatalog::for($provider);
$setup->setupSteps;              // what to do in BambooHR, in order
$setup->credentials;             // key, label, help, example, secret, required

try {
    // Trimmed, limited to the keys the connector reads, normalised — a pasted
    // https://acme.bamboohr.com becomes `acme`; a Workday report URL is pinned to
    // Workday's own hosts and asked for as JSON.
    $credentials = HrisCatalog::credentialsFrom($provider, $request->input('credentials'));

    // A cheap request with the reason when it is refused.
    app(DirectoryConnectors::class)->for($provider)->probe($credentials);
} catch (IncompleteHrisCredentials $e) {
    $e->keys;                    // which fields to mark
} catch (DirectoryConnectionFailed $e) {
    $e->getMessage();            // "… failed (403): the credentials lack permission to read employees."
}
```

## 2. Register the directory and run the first pull on a worker

```php
use Cbox\Id\Directory\Contracts\Directories;
use Cbox\Id\Directory\Contracts\PullDirectories;
use Cbox\Id\Directory\Jobs\SyncPullDirectory;

$directory = app(Directories::class)->registerPull($organization->id, 'BambooHR', $provider, $credentials);

// Optional: HR fields to copy onto each person, and a pace of its own (15..1440 minutes).
app(PullDirectories::class)->setHrisOptions($directory, ['costCenter', 'location']);
app(PullDirectories::class)->setSyncInterval($directory, 30);

SyncPullDirectory::dispatch($directory->id);
```

The credentials are sealed (`SecretBox`, bound to the directory id) and never serialized:
`Directory` hides `credentials` and `bearer_token_hash`. Replace them with
`PullDirectories::replaceCredentials()`, which also makes the next run a full pull.

After that the scheduler pulls every directory whose interval has elapsed
(`cbox-id:directory:sync --due`, every fifteen minutes). `--full` asks an incremental
system for everybody.

## What a pull does

- **Employment decides access.** An employee whose termination date has passed is
  deactivated at the end of that day, whatever the status field still says. Somebody whose
  start date is in the future gets an account on the day (`cbox-id.directory.hris.pre_hire_days`
  moves that earlier). On leave keeps the account.
- **Leavers who never had an account get none.** HR systems report everyone they ever
  employed; only people already in the directory are written to deactivate them.
- **The person is a SCIM user**, stored like a SCIM push: `name`, `emails`, `title`, the
  enterprise extension's `employeeNumber`, `department` and `manager` (`value` = the
  manager's HR employee id), and `urn:cbox-id:params:scim:schemas:extension:hris:1.0:User`
  with the employment status, start and termination dates, department id and custom
  attributes.
- **Departments become groups** (external id `department:{id}`), membership rebuilt from
  the stored people every run, so group → role mappings work exactly as for SCIM groups.
  Two departments with one name are kept apart by id; a department that is gone and empty
  is removed.
- **One bad record costs one record.** An email that belongs to an unlinked account, or an
  employee with no work email, is a `SyncFailure` on the result — external id and a reason
  with no personal data — and the run is `partial`. Such people still count as seen, so a
  data problem never deprovisions somebody who is employed.
- **Incremental runs** ask only for what changed since the last run started (wound back
  five minutes), between full pulls at most `full_sync_hours` apart. They never deprovision
  anybody for being absent; termination dates are swept from what is stored every run.
- **A mass deprovisioning is refused.** A full pull that would deactivate more than
  `deprovision_guard` (half) of the active people deprovisions nobody and says why — an
  API key that lost its reach looks exactly like a mass layoff.
- **Rate limits are waited out.** 429 and 502–504 are retried up to `max_attempts`,
  honouring `Retry-After` or a rate-limit reset header.

Every run is recorded on the directory: `last_sync_started_at`, `last_sync_status`
(`running`, `succeeded`, `partial`, `failed`), `last_sync_stats` (counts and up to
`max_reported_failures` failures), `last_sync_error`. A run holds a per-directory lock, so
the scheduler and a "sync now" never pull the same directory at once.

## Configuration

```php
'directory' => [
    'default_interval_minutes' => 60,
    'hris' => [
        'pre_hire_days' => 0,
        'full_sync_hours' => 24,
        'deprovision_guard' => 0.5,
        'max_attempts' => 5,
        'max_backoff_seconds' => 60,
        'max_reported_failures' => 50,
        'workday_hosts' => ['.workday.com', '.myworkday.com'],
    ],
],
```

## Testing

`FakeHrisProvider` stands in for an HR system: set its employees and departments, make it
incremental (`changed()` is what a "changed since" query answers), or make it refuse.

```php
use Cbox\Id\Directory\DirectoryConnectors;
use Cbox\Id\Directory\Testing\FakeHrisProvider;

app()->instance(DirectoryConnectors::class, new DirectoryConnectors([
    new FakeHrisProvider(employees: [$ada, $grace], departments: [$engineering]),
]));
```

## Your own HR system

Implement `Cbox\Id\Directory\Hris\Contracts\HrisProvider` — or extend `HrisConnector`,
which supplies the retrying client (`http()`), credential reading and the pagination pin —
add a `DirectoryProvider` case for it in your fork, and rebind `DirectoryConnectors` with it.
