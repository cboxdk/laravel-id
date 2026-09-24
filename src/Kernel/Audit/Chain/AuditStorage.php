<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Chain;

use Cbox\AuditChain\Storage\ChainModels;
use Cbox\Id\Kernel\Audit\Models\AuditCheckpoint;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;

/**
 * The tables the platform's audit chain lives in: `audit_logs` and `audit_checkpoints`,
 * partitioned by `environment_id`, through {@see AuditEntry} and {@see AuditCheckpoint}.
 *
 * Stated here rather than taken from `audit-chain.models.*`, so a host's published
 * package config can never point the platform's trail at other tables.
 */
class AuditStorage
{
    public static function models(): ChainModels
    {
        return new ChainModels(AuditEntry::class, AuditCheckpoint::class);
    }
}
