<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Scim;

use Cbox\Id\Api\Contracts\ScimBulkProcessor;
use Cbox\Id\Api\Contracts\ScimGroupResources;
use Cbox\Id\Api\Contracts\ScimResourceEndpoint;
use Cbox\Id\Api\Contracts\ScimUserResources;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Scim\ScimSchema;
use Illuminate\Contracts\Config\Repository;

/**
 * SCIM `/Bulk` (RFC 7644 §3.7).
 *
 * ## Same code as everything else
 *
 * Every operation is dispatched to the very {@see ScimResourceEndpoint} the
 * single-resource controllers call — the same validation, provisioning, error mapping
 * and `If-Match` preconditions (an operation's `version` IS its `If-Match`). The only
 * logic here is bulk logic: parsing operations, resolving `bulkId` references, counting
 * errors, and assembling the BulkResponse.
 *
 * ## Independent operations
 *
 * "The service provider MUST continue performing as many changes as possible and
 * disregard partial failures" (§3.7). Each operation commits or fails on its own; there
 * is no transaction around the request. `failOnErrors` stops processing once that many
 * operations have failed, and the response then lists only what was processed.
 *
 * ## bulkId references
 *
 * A POST names its new resource `bulkId: "qwerty"`; any later string that is exactly
 * `bulkId:qwerty` — in another operation's `path` (`/Users/bulkId:qwerty`) or anywhere in
 * its `data` (a group's `members[].value`, the Enterprise `manager.value`) — is replaced
 * with the created resource's id before that operation runs (§3.7.2). An operation that
 * refers to a POST appearing LATER in the request runs that POST first, which preserves
 * the client's intent as §3.7 requires of any reordering. A reference that cannot be
 * resolved — no such bulkId, its POST failed, or a cycle — fails that operation with
 * `409`, which §3.7.1 allows after a failed attempt.
 *
 * ## Limits
 *
 * `maxOperations` is enforced here and `maxPayloadSize` by the controller (before the
 * body is decoded); exceeding either is a `413` whose detail names the limit (§3.7.4).
 */
class DefaultScimBulkProcessor implements ScimBulkProcessor
{
    public const DEFAULT_MAX_OPERATIONS = 1000;

    public const DEFAULT_MAX_PAYLOAD_SIZE = 1048576;

    public function __construct(
        private readonly ScimUserResources $users,
        private readonly ScimGroupResources $groups,
        private readonly Repository $config,
    ) {}

    public function maxOperations(): int
    {
        return $this->positive('cbox-id.scim.bulk.max_operations', self::DEFAULT_MAX_OPERATIONS);
    }

    public function maxPayloadSize(): int
    {
        return $this->positive('cbox-id.scim.bulk.max_payload_size', self::DEFAULT_MAX_PAYLOAD_SIZE);
    }

    public function process(Directory $directory, array $request): ScimOutcome
    {
        $request = array_change_key_case($request, CASE_LOWER);
        $operations = $request['operations'] ?? null;

        if (! is_array($operations) || $operations === [] || ! array_is_list($operations)) {
            return ScimOutcome::error(400, 'A bulk request must carry a non-empty "Operations" array (RFC 7644 §3.7).', 'invalidSyntax');
        }

        if (count($operations) > $this->maxOperations()) {
            return ScimOutcome::error(413, sprintf(
                'The number of operations (%d) exceeds the maxOperations (%d).',
                count($operations),
                $this->maxOperations(),
            ));
        }

        $failOnErrors = $request['failonerrors'] ?? null;

        if ($failOnErrors !== null && (! is_int($failOnErrors) || $failOnErrors < 1)) {
            return ScimOutcome::error(400, '"failOnErrors" must be a positive integer (RFC 7644 §3.7).', 'invalidValue');
        }

        $run = new ScimBulkRun($directory, $this->parse($operations), $failOnErrors);

        foreach (array_keys($run->operations) as $index) {
            if ($run->stopped) {
                break;
            }

            $this->execute($run, $index);
        }

        ksort($run->results);

        return ScimOutcome::resource([
            'schemas' => [ScimSchema::BULK_RESPONSE_URN],
            'Operations' => array_values($run->results),
        ]);
    }

    /**
     * Read each raw operation into a {@see ScimBulkOperation}. A malformed one carries
     * the reason in `invalid` and fails on its own, not the whole request.
     *
     * @param  list<mixed>  $operations
     * @return list<ScimBulkOperation>
     */
    private function parse(array $operations): array
    {
        $parsed = [];
        $bulkIds = [];

        foreach ($operations as $raw) {
            $operation = ScimBulkOperation::parse($raw);

            if ($operation->invalid === null && $operation->bulkId !== null) {
                // "unique within a bulk request" (§3.7) — a second definition would make
                // every reference to it ambiguous.
                if (isset($bulkIds[$operation->bulkId])) {
                    $operation = $operation->invalidate(sprintf('The bulkId "%s" is used by more than one operation.', $operation->bulkId));
                } else {
                    $bulkIds[$operation->bulkId] = true;
                }
            }

            $parsed[] = $operation;
        }

        return $parsed;
    }

    private function execute(ScimBulkRun $run, int $index): void
    {
        if (array_key_exists($index, $run->results) || $run->stopped) {
            return;
        }

        $operation = $run->operations[$index];

        if ($operation->invalid !== null) {
            $this->record($run, $index, $operation->summary(), ScimOutcome::error(400, $operation->invalid, 'invalidSyntax'));

            return;
        }

        $run->visiting[$index] = true;

        foreach ($operation->references() as $reference) {
            if (isset($run->resolved[$reference])) {
                continue;
            }

            $definer = $run->definerOf($reference);

            if ($definer !== null && ! array_key_exists($definer, $run->results)) {
                if (isset($run->visiting[$definer])) {
                    unset($run->visiting[$index]);
                    $this->record($run, $index, $operation->summary(), ScimOutcome::error(409, sprintf('The bulkId reference "%s" is circular.', $reference), 'invalidValue'));

                    return;
                }

                // A forward reference: create what it names first.
                $this->execute($run, $definer);

                if ($run->stopped) {
                    unset($run->visiting[$index]);

                    return;
                }
            }

            if (! isset($run->resolved[$reference])) {
                unset($run->visiting[$index]);
                $this->record($run, $index, $operation->summary(), ScimOutcome::error(409, sprintf('The bulkId reference "%s" cannot be resolved.', $reference), 'invalidValue'));

                return;
            }
        }

        unset($run->visiting[$index]);

        $resolved = $operation->resolve($run->resolved);
        $endpoint = $resolved->resource === 'Groups' ? $this->groups : $this->users;
        $outcome = $this->dispatch($run->directory, $endpoint, $resolved);

        if ($resolved->method === 'POST' && ! $outcome->failed() && $resolved->bulkId !== null && $outcome->id() !== null) {
            $run->resolved[$resolved->bulkId] = $outcome->id();
        }

        $summary = $resolved->summary();

        // A `location` for every operation except a failed POST (§3.7.3).
        if ($resolved->id !== null) {
            $summary['location'] = $outcome->location ?? $endpoint->location($resolved->id);
        } elseif ($outcome->location !== null) {
            $summary['location'] = $outcome->location;
        }

        $this->record($run, $index, $summary, $outcome);
    }

    private function dispatch(Directory $directory, ScimResourceEndpoint $endpoint, ScimBulkOperation $operation): ScimOutcome
    {
        $id = $operation->id ?? '';

        return match ($operation->method) {
            'POST' => $endpoint->create($directory, $operation->data),
            'PUT' => $endpoint->replace($directory, $id, $operation->data, $operation->version),
            'PATCH' => $endpoint->patch($directory, $id, $operation->data, $operation->version),
            default => $endpoint->delete($directory, $id, $operation->version),
        };
    }

    /**
     * @param  array<string, mixed>  $summary
     */
    private function record(ScimBulkRun $run, int $index, array $summary, ScimOutcome $outcome): void
    {
        $summary['status'] = (string) $outcome->status;

        if ($outcome->failed()) {
            // "When indicating a response with an HTTP status other than a 200-series
            // response, the response body MUST be included" (§3.7).
            $summary['response'] = $outcome->body;
            $run->errors++;

            if ($run->failOnErrors !== null && $run->errors >= $run->failOnErrors) {
                $run->stopped = true;
            }
        } elseif ($outcome->version !== null && ($summary['method'] ?? null) !== 'DELETE') {
            $summary['version'] = $outcome->version;
        }

        $run->results[$index] = $summary;
    }

    private function positive(string $key, int $default): int
    {
        $value = $this->config->get($key);

        return is_numeric($value) && (int) $value > 0 ? (int) $value : $default;
    }
}
