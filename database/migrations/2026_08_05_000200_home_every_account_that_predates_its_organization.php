<?php

declare(strict_types=1);

use Cbox\Id\Platform\AccountProvisioner;
use Cbox\Id\Platform\PlatformRoot;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Give every account that predates `accounts.organization_id` its home in the
 * platform root.
 *
 * WHY. The column was added nullable and never backfilled — `2026_07_25_000400` is an
 * `addColumn` and nothing else — and it is written in exactly two places, both at
 * CREATION time ({@see AccountProvisioner::homeAccount()} and the app's signup
 * provisioner). So every account created before that date has null, permanently.
 *
 * That is not a cosmetic gap. `ConsoleScope::accountRole()` answers "what does the
 * acting person hold on the organization they are administering" with two conditions,
 * the second being that the acting organization is the one this account owns —
 * `$member->account->organization_id === $organizationId`. Against null that is false
 * for every organization, so an account owner gets null, `ownsIdentityProviders()`
 * answers false, and the whole identity-platform area of the console — projects,
 * members, API keys, billing, settings — is simply absent for the person who owns it.
 *
 * NO TEST CAN SEE THIS, which is why it reached a working deployment. Every fixture in
 * both suites builds its account through `AccountProvisioner::provision()`, and that
 * homes the account on the way past. The only way to hold an unhomed account is to have
 * created it before this column existed, which no test does and every real deployment
 * did. The accompanying test provisions one and then un-homes it, so the gap has a
 * fixture at last.
 *
 * It is also not only a legacy problem: `homeAccount()` returns SILENTLY when there is
 * no platform root yet, which is exactly the window the installer and the first-run
 * screen run in. An account provisioned in that window is unhomed on a brand-new
 * deployment too.
 *
 * RAW INSERTS, not `OrganizationService::create()`. The service emits a domain event and
 * writes an audit entry per organization. A migration runs during deploy, on a host
 * whose queue, listeners and audit chain are mid-rollout, and a backfill of a thousand
 * accounts should not put a thousand events on a queue. The rows it writes are exactly
 * the ones the service writes — the organization plus its depth-0 closure self-row —
 * and the assertion that they stay identical belongs in the test, not in a coupling.
 */
return new class extends Migration
{
    public function up(): void
    {
        $root = DB::table('environments')->where('is_default', true)->value('id');

        // No platform root means the deployment is not installed: there is nowhere to
        // home an account INTO, and inventing an environment here would put the
        // platform's own people somewhere no installer chose. {@see PlatformRoot}
        // degrades the same way rather than guessing, and so does `homeAccount()`.
        if (! is_string($root) || $root === '') {
            return;
        }

        $unhomed = DB::table('accounts')
            ->whereNull('organization_id')
            ->orderBy('id')
            ->get(['id', 'name']);

        if ($unhomed->isEmpty()) {
            return;
        }

        // Read the taken slugs ONCE, then reserve into the same set as we go. The
        // provisioner re-queries per account because it creates one at a time; doing
        // that here would be a query per account, and — worse — would not see the slugs
        // this same loop has already reserved, so two accounts both named "Acme" would
        // both take `acme` and the second insert would hit the (environment_id, slug)
        // unique key mid-backfill.
        $taken = DB::table('organizations')
            ->where('environment_id', $root)
            ->pluck('slug')
            ->map(static fn (mixed $slug): string => is_string($slug) ? $slug : '')
            ->all();
        $taken = array_flip($taken);

        $now = now();

        foreach ($unhomed as $account) {
            $name = is_string($account->name) && $account->name !== '' ? $account->name : 'Account';
            $slug = $this->reserve($name, $taken);
            $taken[$slug] = true;

            // Lowercase, because `HasUlids::newUniqueId()` is — an id generated in the
            // other case here would compare unequal to itself in every binary string
            // join the platform makes on it.
            $organizationId = strtolower((string) Str::ulid());

            DB::transaction(function () use ($organizationId, $root, $account, $name, $slug, $now): void {
                DB::table('organizations')->insert([
                    'id' => $organizationId,
                    'environment_id' => $root,
                    'name' => $name,
                    'slug' => $slug,
                    'parent_id' => null,
                    'type' => 'customer',
                    'status' => 'active',
                    'settings' => '{}',
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);

                // The depth-0 self-row. `ClosureOrganizationHierarchy::attach()` writes
                // it for every organization including a root one, and the hierarchy
                // reads are closure-only — an organization without it is invisible to
                // its own descendant query, not merely childless.
                DB::table('organization_closure')->insert([
                    'id' => strtolower((string) Str::ulid()),
                    'environment_id' => $root,
                    'ancestor_id' => $organizationId,
                    'descendant_id' => $organizationId,
                    'depth' => 0,
                ]);

                // Guarded on null against a CONCURRENT writer — not against a re-run. A
                // second run is already a no-op because the select above filters on the
                // same column; what this catches is an account homed by another deploy,
                // or by a signup, in the window between that select and this update,
                // which would otherwise be moved to a second organization and leave the
                // first orphaned with nothing pointing at it.
                //
                // It therefore has NO TEST, and cannot have one in this suite: a single
                // process cannot produce the interleaving. Said plainly, rather than left
                // next to the re-run test, which passes with or without this line and
                // would read as if it proved it.
                DB::table('accounts')
                    ->where('id', $account->id)
                    ->whereNull('organization_id')
                    ->update(['organization_id' => $organizationId, 'updated_at' => $now]);
            });
        }
    }

    /**
     * NOT REVERSED, deliberately.
     *
     * Reversing means deleting organizations, and by the time anyone rolls back, those
     * organizations are what the account's members, its SSO connection and its audit
     * scope hang off — the whole point of homing an account is that other rows come to
     * reference it. A `down()` that deleted them would take those with it, and one that
     * only nulled the column would leave them orphaned in the platform root with nothing
     * naming them. `2026_07_25_000400::down()` already drops the column outright, which
     * is the honest rollback for this pair.
     */
    public function down(): void {}

    /**
     * @param  array<string, mixed>  $taken
     */
    private function reserve(string $name, array $taken): string
    {
        $base = Str::slug($name);
        $base = $base === '' ? 'account' : $base;

        $slug = $base;
        $suffix = 1;

        while (array_key_exists($slug, $taken)) {
            $slug = $base.'-'.(++$suffix);
        }

        return $slug;
    }
};
