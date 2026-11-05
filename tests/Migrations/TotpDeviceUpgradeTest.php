<?php

declare(strict_types=1);

use Cbox\Id\Tests\Support\ThrowawayDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

it('adds slots and names without changing an existing TOTP or SMS credential', function (): void {
    [$connection, $cleanup] = ThrowawayDatabase::open('totp_upgrade');
    $original = DB::getDefaultConnection();
    try {
        DB::setDefaultConnection($connection);
        Schema::clearResolvedInstance('db.schema');
        $base = require dirname(__DIR__, 2).'/database/migrations/2026_01_01_001300_create_mfa_factors_table.php';
        $base->up();
        $before = [];
        foreach (['totp', 'sms'] as $type) {
            $before[] = [
                'id' => str_pad($type, 26, '0'), 'environment_id' => 'env_test',
                'user_id' => 'existing-user', 'type' => $type,
                'secret_encrypted' => 'existing-sealed-'.$type,
                'confirmed_at' => '2026-01-01 00:00:00',
                'created_at' => '2026-01-01 00:00:00', 'updated_at' => '2026-01-01 00:00:00',
            ];
        }
        DB::table('mfa_factors')->insert($before);
        $migration = require dirname(__DIR__, 2).'/database/migrations/2026_11_05_000200_add_named_totp_devices.php';
        $migration->up();
        foreach ($before as $old) {
            $row = DB::table('mfa_factors')->where('id', $old['id'])->first();
            expect($row->secret_encrypted)->toBe($old['secret_encrypted'])
                ->and($row->confirmed_at)->toBe($old['confirmed_at'])
                ->and($row->name)->toBe('')
                ->and($row->slot)->toBe(0);
        }
        $migration->down();
        expect(DB::table('mfa_factors')->count())->toBe(2)
            ->and(Schema::hasColumn('mfa_factors', 'slot'))->toBeFalse();
    } finally {
        DB::setDefaultConnection($original);
        Schema::clearResolvedInstance('db.schema');
        $cleanup();
    }
});
