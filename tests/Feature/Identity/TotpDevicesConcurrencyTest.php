<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Contracts\TotpDevices;
use Cbox\Id\Identity\Exceptions\TotpDeviceRefused;
use Cbox\Id\Identity\Models\MfaFactor;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('serializes simultaneous authenticator changes', function (string $operation): void {
    $this->fakeAudit();
    $devices = app(TotpDevices::class);
    $mfa = app(Mfa::class);
    $totp = app(TotpAuthenticator::class);
    $user = 'concurrent-totp';
    $apps = [];
    if ($operation !== 'enroll') {
        for ($i = 0; $i < 2; $i++) {
            $app = $devices->enrollDevice($user, 'race@example.test', 'Phone '.$i);
            $devices->confirmDevice($user, $app->id, $totp->codeAt($app->secret, time() - 30));
            $apps[] = $app;
        }
    }
    // Forked connections must see committed fixtures and never share a PDO socket.
    DB::commit();
    DB::disconnect();
    $results = sys_get_temp_dir().'/totp-race-'.bin2hex(random_bytes(8));
    mkdir($results);
    $pids = [];
    for ($i = 0; $i < 2; $i++) {
        $pid = pcntl_fork();
        expect($pid)->not->toBe(-1);
        if ($pid === 0) {
            // Both processes wait until the parent has started them.
            while (! file_exists($results.'/go')) {
                usleep(1000);
            }
            try {
                $result = match ($operation) {
                    'remove' => $devices->removeDevice($user, $apps[$i]->id),
                    'verify' => $mfa->verifyTotp($user, $totp->codeAt($apps[0]->secret, time())),
                    default => $devices->enrollDevice($user, 'race@example.test', 'Phone '.$i)->id,
                };
            } catch (TotpDeviceRefused $refused) {
                $result = $refused->reason;
            } catch (Throwable $error) {
                $result = 'ERROR: '.$error::class.': '.$error->getMessage();
            }
            file_put_contents($results.'/'.$i.'.json', json_encode($result, JSON_THROW_ON_ERROR));
            posix_kill(posix_getpid(), SIGKILL);
        }
        $pids[] = $pid;
    }
    touch($results.'/go');
    foreach ($pids as $pid) {
        pcntl_waitpid($pid, $status);
    }
    $answers = [];
    for ($i = 0; $i < 2; $i++) {
        $answers[] = json_decode(file_get_contents($results.'/'.$i.'.json'), true, flags: JSON_THROW_ON_ERROR);
    }
    $count = MfaFactor::query()->where('user_id', $user)->count();
    MfaFactor::query()->where('user_id', $user)->delete();
    array_map('unlink', glob($results.'/*'));
    rmdir($results);
    // Restore the test wrapper after committed cleanup. RefreshDatabase can reuse
    // the verified schema for the next case instead of migrating every table again.
    DB::beginTransaction();

    if ($operation === 'enroll') {
        expect($count)->toBe(2)->and($answers[0])->not->toBe($answers[1]);
    } elseif ($operation === 'remove') {
        expect($count)->toBe(1)->and($answers)->toContain(true, 'last_device');
    } else {
        expect($answers)->toContain(true, false);
    }
})->with(['enroll', 'remove', 'verify'])->skip(
    fn (): bool => DB::connection()->getDriverName() === 'sqlite' || ! function_exists('pcntl_fork'),
    'needs PostgreSQL or MySQL and pcntl',
);
