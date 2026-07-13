<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Outstanding SP-initiated SAML AuthnRequest ids, so the ACS can enforce
        // InResponseTo (RFC/SAML) without depending on the browser session — the
        // ACS is a cross-site POST where the session cookie (SameSite=Lax) is absent.
        Schema::create('saml_auth_requests', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('request_id')->unique();
            $table->string('connection_id')->index();
            $table->timestamp('expires_at');
            $table->timestamp('consumed_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('saml_auth_requests');
    }
};
