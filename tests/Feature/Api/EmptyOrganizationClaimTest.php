<?php

declare(strict_types=1);

use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipRole;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('distinguishes an authoritative empty organization list from an ungranted scope', function (): void {
    User::query()->create(['id' => 'membership-reader', 'email' => 'reader@example.test', 'status' => UserStatus::Active]);
    $client = $this->makeClient(['openid', 'organizations']);
    $issuer = app(TokenIssuer::class);
    $scoped = $issuer->issueForUser($client->client, 'membership-reader', null, ['openid', 'organizations'])->token;
    $unscoped = $issuer->issueForUser($client->client, 'membership-reader', null, ['openid'])->token;
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$scoped])->assertOk()->assertJsonPath('organizations', []);
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$unscoped])->assertOk()->assertJsonMissingPath('organizations');

    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'membership-reader', MembershipRole::Member);
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$scoped])->assertOk()->assertJsonCount(1, 'organizations')->assertJsonPath('organizations.0.id', $org->id);
    app(Memberships::class)->remove($org->id, 'membership-reader');
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$scoped])->assertOk()->assertJsonPath('organizations', []);
});
