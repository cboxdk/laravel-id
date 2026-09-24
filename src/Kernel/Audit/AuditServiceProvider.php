<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit;

use Cbox\AuditChain\AuditChainServiceProvider;
use Cbox\AuditChain\Contracts\AuditChain;
use Cbox\AuditChain\Contracts\ChainContext;
use Cbox\AuditChain\Contracts\ChainInventory;
use Cbox\AuditChain\Storage\DatabaseChainInventory;
use Cbox\Id\Kernel\Audit\Chain\AuditLogChain;
use Cbox\Id\Kernel\Audit\Chain\AuditStorage;
use Cbox\Id\Kernel\Audit\Chain\EnvironmentChainContext;
use Cbox\Id\Kernel\Audit\Console\CheckpointCommand;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\ServiceProvider;

/**
 * The platform's audit trail, built on cboxdk/laravel-audit-chain.
 *
 * `AuditLog` stays the platform's contract and entry point. The package's own contracts
 * are pointed at the same trail, so its `audit-chain:checkpoint` and `audit-chain:verify`
 * commands (and anything else written against `AuditChain`) sweep `audit_logs` through
 * the platform's AuditLog stack, each chain inside its own environment:
 *
 * - `AuditChain`     → {@see AuditLogChain} (the decorated AuditLog, per environment)
 * - `ChainInventory` → the `audit_logs` / `audit_checkpoints` tables
 * - `ChainContext`   → {@see EnvironmentChainContext}
 *
 * The package's other bindings (its Ed25519 signer, its v1 codec, its config-driven
 * models) are left alone: the platform's chain never reads them, so a host can use the
 * package for its own purposes without touching this trail. `CheckpointAnchor` is the
 * one package binding the platform DOES use — bind or configure it
 * (`audit-chain.anchor.*`) to export the platform's checkpoints.
 */
class AuditServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // Registered here as well as by package discovery, so the package's defaults
        // (the CheckpointAnchor above all) exist wherever this provider runs — a
        // Testbench app, or a host with discovery turned off. Registering a provider
        // twice is a no-op.
        $this->app->register(AuditChainServiceProvider::class);

        $this->app->singleton(AuditLog::class, DatabaseAuditLog::class);
        $this->app->singleton(Checkpointer::class);

        $this->app->singleton(AuditChain::class, static fn (): AuditChain => new AuditLogChain);
        $this->app->singleton(ChainInventory::class, static fn (): ChainInventory => new DatabaseChainInventory(AuditStorage::models()));
        $this->app->singleton(ChainContext::class, EnvironmentChainContext::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([CheckpointCommand::class]);
        }

        // OFF BY DEFAULT — the flag is a safety catch, not a preference.
        //
        // A signed checkpoint is permanent, exportable evidence about the chain's
        // hashes AS THEY ARE TODAY. The GDPR-erasure design still to come needs one
        // re-chain of every existing row (hash the CIPHERTEXT of `ip` and `context`
        // instead of the plaintext), and after that re-chain any checkpoint signed
        // beforehand would report tampering that never happened. Nothing has ever
        // signed one — `audit_checkpoints` is empty in production — so the window is
        // still open, and the first scheduled run closes it forever.
        //
        // Enable it, and get the tail-deletion detection the chain cannot provide on
        // its own, once the ordering in UPGRADING.md has been followed — or right
        // away on a deployment with no such migration ahead of it. The command is
        // always available to run by hand either way.
        if (config('cbox-id.audit.checkpoint.schedule', false) === true) {
            $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
                $schedule->command(CheckpointCommand::class)
                    ->dailyAt($this->scheduleTime())
                    ->name('cbox-id:audit:checkpoint')
                    ->withoutOverlapping();
            });
        }
    }

    /**
     * Daily and off-peak, like the prune sweep, and half an hour ahead of it so the
     * two maintenance passes keep a fixed, readable order. (Not a dependency: prune
     * cannot touch `audit_logs` at all.)
     *
     * A malformed value falls back rather than leaving the pass unscheduled — a typo
     * in a time string must not silently switch a tamper control off.
     */
    private function scheduleTime(): string
    {
        $time = config('cbox-id.audit.checkpoint.time', '02:40');

        return is_string($time) && preg_match('/^\d{1,2}:\d{2}$/', $time) === 1 ? $time : '02:40';
    }
}
