<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Where an app says its old login lives, and whether a person has agreed to it.
 *
 * The declaration arrives through the manifest — the same authenticated channel an app
 * already uses to declare its roles and permissions, versioned with its deploy. That is
 * the right home for it: an operator pasting a URL into a console and a secret into an env
 * file is two places that drift.
 *
 * APPROVAL IS A SEPARATE COLUMN BECAUSE IT IS A SEPARATE ACT. Everything else an app
 * declares affects only that app; this one puts a URL on the ENVIRONMENT'S sign-in path,
 * where every unknown email and the password typed with it is offered to it. A client
 * holding `apps.manifest` that could turn that on by itself is a credential harvester
 * with a scope for it — so the row exists the moment it is declared, and does nothing
 * until `approved_at` is set by a person.
 *
 * The URL is stored in the clear on purpose: an operator has to be able to READ it before
 * approving, and a value nobody can see is a value nobody can check. The secret is sealed,
 * because it is the only thing proving a request came from us.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('legacy_login_declarations', function (Blueprint $table): void {
            // `string(…, 26)`, never `ulid()`: PostgreSQL implements CHAR as blank-padded
            // `bpchar`, so a value comes back padded and a strict comparison fails. See
            // SchemaPortabilityTest.
            $table->string('id', 26)->primary();

            // ONE PER ENVIRONMENT, not per client. The sign-in path is the environment's,
            // so two apps cannot each nominate a different place to send passwords — the
            // second declaration replaces the first and loses its approval, which is the
            // event an operator most needs to see.
            $table->string('environment_id', 26)->unique();

            /*
             * Which app proposed it. Kept so the console can show "this came from Acme
             * Web" rather than an anonymous URL somebody has to take on trust.
             *
             * NO LENGTH, like every other `client_id` column in this package. It was
             * `string('client_id', 26)` — the ULID width of the three columns above it —
             * and a client id is not a ULID: `ClientRegistryService` mints
             * `'cid_'.Str::ulid()`, which is thirty characters. PostgreSQL refused the
             * insert outright (`22001`), MySQL in strict mode refused it and without
             * strict mode truncated the id to one that matches no client, and SQLite
             * ignores declared widths so nothing said anything. The feature was unusable
             * on both engines anybody deploys on.
             */
            $table->string('client_id')->index();

            $table->string('url', 512);
            $table->text('secret_encrypted');

            $table->timestamp('approved_at')->nullable();
            $table->string('approved_by', 26)->nullable();

            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('legacy_login_declarations');
    }
};
