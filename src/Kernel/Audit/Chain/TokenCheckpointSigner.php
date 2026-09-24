<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Chain;

use Cbox\AuditChain\Contracts\CheckpointSigner;
use Cbox\AuditChain\Exceptions\CheckpointClaimsMalformed;
use Cbox\AuditChain\Exceptions\CheckpointSignatureInvalid;
use Cbox\AuditChain\ValueObjects\CheckpointClaims;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Throwable;

/**
 * Signs audit checkpoints as the Crypto kernel's JWTs — the format every existing
 * `audit_checkpoints.signature` is in — so checkpoints signed before the chain moved
 * into cboxdk/laravel-audit-chain keep verifying, and new ones are signed the same way.
 *
 * Signing: the claims `{typ, scope, up_to_sequence, root_hash, iat}`, in that order,
 * with `typ` = `cbox-id.audit.checkpoint`, through {@see TokenSigner::sign()} with its
 * default algorithm and the ACTIVE ENVIRONMENT'S key. The partition is not a claim: the
 * key is already per environment, and the pre-extraction format never carried it, so
 * claims come back with `partition: null` and verification takes the environment on the
 * row's word (see CheckpointClaims).
 *
 * Verification: {@see TokenSigner::verify()} pinned to RS256 and ES256, against the
 * active environment's verification keys. Claims are then read exactly as the
 * pre-extraction code read them: `scope` and `root_hash` must be strings and
 * `up_to_sequence` a number (compared as an integer). A payload that fails that is a
 * payload mismatch, not a bad signature — as before. `typ` is not checked, as before.
 */
class TokenCheckpointSigner implements CheckpointSigner
{
    public const TYPE = 'cbox-id.audit.checkpoint';

    /**
     * The algorithms a checkpoint signature may use. An explicit allow-list: the token
     * never gets to choose.
     */
    public const ALLOWED = [SigningAlg::RS256, SigningAlg::ES256];

    public function __construct(
        private readonly TokenSigner $signer,
    ) {}

    public function sign(CheckpointClaims $claims): string
    {
        return $this->signer->sign([
            'typ' => self::TYPE,
            'scope' => $claims->scope,
            'up_to_sequence' => $claims->upToSequence,
            'root_hash' => $claims->rootHash,
            'iat' => $claims->issuedAt,
        ]);
    }

    public function verify(string $token): CheckpointClaims
    {
        try {
            $claims = $this->signer->verify($token, self::ALLOWED);
        } catch (Throwable $failure) {
            throw CheckpointSignatureInvalid::because($failure->getMessage(), $failure);
        }

        $scope = $claims->get('scope');
        $upToSequence = $claims->get('up_to_sequence');
        $rootHash = $claims->get('root_hash');
        $issuedAt = $claims->get('iat');

        if (! is_string($scope) || ! (is_int($upToSequence) || is_float($upToSequence)) || ! is_string($rootHash)) {
            throw CheckpointClaimsMalformed::because('scope, up_to_sequence and root_hash are required');
        }

        return new CheckpointClaims(
            $scope,
            (int) $upToSequence,
            $rootHash,
            is_int($issuedAt) || is_float($issuedAt) ? (int) $issuedAt : 0,
        );
    }
}
