<?php

declare(strict_types=1);

namespace Cbox\Id\Console;

use Cbox\Id\Identity\Contracts\UserImport;
use Cbox\Id\Identity\ValueObjects\ImportedUser;
use Cbox\Id\Identity\ValueObjects\ImportOptions;
use Cbox\Id\Identity\ValueObjects\ImportResult;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Organization\Models\Organization;
use Generator;
use Illuminate\Console\Command;

use function Laravel\Prompts\intro;
use function Laravel\Prompts\note;
use function Laravel\Prompts\outro;
use function Laravel\Prompts\table;

/**
 * `cbox-id:users:import` — the CLI on-ramp for the migration wedge. Point it at a
 * CSV or JSON export from your old provider (Auth0/Cognito/Firebase/a SQL app),
 * INCLUDING each user's existing password hash, and it streams them into the
 * platform so they sign in on day one — each foreign hash upgraded to argon2id on
 * first successful login (see {@see UserImport}).
 *
 * Columns / keys: `email`, `name`, `password_hash` (a pre-hashed credential) OR
 * `password` (plaintext), `email_verified`, `role`, plus any extra columns which
 * are carried through as attributes.
 */
final class ImportUsersCommand extends Command
{
    protected $signature = 'cbox-id:users:import
        {file : Path to the CSV or JSON file of users to import}
        {--org= : The organization ID the imported users join}
        {--format=csv : Source format — csv or json}
        {--upsert : Update users that already exist instead of skipping them}
        {--role=member : Org membership role for rows without an explicit role}';

    protected $description = 'Bulk-import users (with existing password hashes) from another provider';

    public function handle(UserImport $import, EnvironmentContext $context): int
    {
        intro('Cbox ID — bulk user import');

        $fileArg = $this->argument('file');
        $file = is_string($fileArg) ? $fileArg : '';
        if ($file === '' || ! is_file($file) || ! is_readable($file)) {
            $this->error("File not found or unreadable: {$file}");

            return self::FAILURE;
        }

        $orgId = $this->stringOption('org');
        if ($orgId === null) {
            $this->error('The --org option is required (the organization the imported users join).');

            return self::FAILURE;
        }

        $format = strtolower($this->stringOption('format') ?? 'csv');
        if (! in_array($format, ['csv', 'json'], true)) {
            $this->error("Unknown --format [{$format}] — use csv or json.");

            return self::FAILURE;
        }

        // The org must exist; it also anchors which environment the users land in.
        $org = $context->withoutScope(fn (): ?Organization => Organization::query()->whereKey($orgId)->first());
        if (! $org instanceof Organization) {
            $this->error("Organization [{$orgId}] not found.");

            return self::FAILURE;
        }

        $options = new ImportOptions(
            upsert: (bool) $this->option('upsert'),
            defaultRole: $this->stringOption('role') ?? 'member',
        );

        $doImport = fn (): ImportResult => $import->import($orgId, $this->rows($file, $format), $options);

        // The users MUST land in the target org's own environment — the org is the
        // source of truth for where its members live. When an environment is already
        // ambient (a request, or a test) it must BE the org's; a mismatch would
        // stamp the users into the wrong plane, so refuse rather than silently
        // import there. A bare console invocation has none, so we pin it from the org.
        $orgEnvironmentId = $org->getAttribute('environment_id');

        if ($context->has()) {
            if ($context->requireEnvironment()->environmentKey() !== $orgEnvironmentId) {
                $this->error("The active environment is not organization [{$orgId}]'s environment.");

                return self::FAILURE;
            }

            $result = $doImport();
        } else {
            $environment = $context->withoutScope(
                fn (): ?Environment => Environment::query()->whereKey($orgEnvironmentId)->first(),
            );

            if (! $environment instanceof Environment) {
                $this->error("Could not resolve the environment for organization [{$orgId}].");

                return self::FAILURE;
            }

            $result = $context->runAs($environment, $doImport);
        }

        $this->report($result);

        return $result->failed() ? self::FAILURE : self::SUCCESS;
    }

    private function report(ImportResult $result): void
    {
        note(sprintf(
            "Imported: %d\nUpdated:  %d\nSkipped:  %d\nErrors:   %d\nTotal:    %d",
            $result->imported,
            $result->updated,
            $result->skipped,
            $result->errorCount(),
            $result->total(),
        ), $result->failed() ? 'Done with errors' : 'Done');

        if ($result->failed()) {
            table(
                ['Row', 'Email', 'Reason'],
                array_map(
                    static fn ($e): array => [(string) $e->row, $e->email, $e->reason],
                    $result->errors,
                ),
            );
        }

        $result->failed()
            ? outro("{$result->errorCount()} row(s) could not be imported — see above.")
            : outro('All rows processed.');
    }

    /**
     * @return Generator<int, ImportedUser>
     */
    private function rows(string $file, string $format): Generator
    {
        return $format === 'json' ? $this->jsonRows($file) : $this->csvRows($file);
    }

    /**
     * @return Generator<int, ImportedUser>
     */
    private function csvRows(string $file): Generator
    {
        $handle = fopen($file, 'rb');
        if ($handle === false) {
            return;
        }

        try {
            $header = fgetcsv($handle);
            if (! is_array($header)) {
                return;
            }

            /** @var list<string> $columns */
            $columns = array_map(static fn ($c): string => is_string($c) ? trim($c) : '', $header);

            while (($record = fgetcsv($handle)) !== false) {
                if ($record === [null]) {
                    continue; // blank line
                }

                $data = [];
                foreach ($columns as $i => $column) {
                    if ($column === '') {
                        continue;
                    }
                    $value = $record[$i] ?? null;
                    $data[$column] = is_string($value) ? $value : '';
                }

                yield $this->toImportedUser($data);
            }
        } finally {
            fclose($handle);
        }
    }

    /**
     * @return Generator<int, ImportedUser>
     */
    private function jsonRows(string $file): Generator
    {
        $decoded = json_decode((string) file_get_contents($file), true);
        if (! is_array($decoded)) {
            return;
        }

        foreach ($decoded as $entry) {
            if (is_array($entry)) {
                /** @var array<string, mixed> $entry */
                yield $this->toImportedUser($entry);
            }
        }
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private function toImportedUser(array $data): ImportedUser
    {
        $known = ['email', 'name', 'password_hash', 'password', 'email_verified', 'role', 'attributes'];

        $attributes = [];
        if (isset($data['attributes']) && is_array($data['attributes'])) {
            foreach ($data['attributes'] as $key => $value) {
                $attributes[(string) $key] = $value;
            }
        }
        foreach ($data as $key => $value) {
            if (! in_array($key, $known, true)) {
                $attributes[$key] = $value;
            }
        }

        return new ImportedUser(
            email: $this->str($data, 'email') ?? '',
            name: $this->str($data, 'name'),
            passwordHash: $this->str($data, 'password_hash'),
            password: $this->str($data, 'password'),
            emailVerified: $this->truthy($data['email_verified'] ?? false),
            attributes: $attributes,
            role: $this->str($data, 'role'),
        );
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private function str(array $data, string $key): ?string
    {
        $value = $data[$key] ?? null;

        if (! is_scalar($value)) {
            return null;
        }

        $string = trim((string) $value);

        return $string === '' ? null : $string;
    }

    private function truthy(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value)) {
            return $value === 1;
        }

        return is_string($value) && in_array(strtolower(trim($value)), ['1', 'true', 'yes', 'y'], true);
    }

    private function stringOption(string $key): ?string
    {
        $value = $this->option($key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
