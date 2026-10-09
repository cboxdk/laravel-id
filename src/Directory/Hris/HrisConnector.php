<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Hris;

use Cbox\Id\Directory\Contracts\DirectoryConnector;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\Hris\Contracts\HrisProvider;
use Cbox\Id\Directory\Hris\Support\HrisHttp;
use Cbox\Id\Directory\Hris\ValueObjects\HrisSyncOptions;
use Cbox\Id\Directory\ValueObjects\DirectoryGroupSnapshot;

/**
 * What every HR-system connector shares: the plain {@see DirectoryConnector}
 * half derived from the employment half, credential reading, the retrying client, and the
 * pagination pin.
 *
 * `fetchUsers()` / `fetchGroups()` exist so an HR system is still a directory connector to
 * anything that only knows that contract. The sync itself never calls them — it runs the
 * HR-aware path, {@see HrisDirectorySync} — so they take the simple route: everybody the
 * mapper would give an account, and departments with their currently employed members.
 */
abstract class HrisConnector implements HrisProvider
{
    public function fetchUsers(array $credentials): iterable
    {
        $mapper = HrisEmployeeMapper::fromConfig();

        foreach ($this->fetchEmployees($credentials, new HrisSyncOptions) as $employee) {
            $user = $mapper->toScimUser($employee, $this->provider());

            if ($user !== null) {
                yield $user;
            }
        }
    }

    public function fetchGroups(array $credentials): iterable
    {
        $options = new HrisSyncOptions;
        $mapper = HrisEmployeeMapper::fromConfig();
        $names = [];
        $members = [];

        foreach ($this->fetchDepartments($credentials, $options) as $department) {
            $names[$department->id] = $department->name;
        }

        foreach ($this->fetchEmployees($credentials, $options) as $employee) {
            $key = HrisEmployeeMapper::departmentKey($employee);

            if ($key === null || ! $mapper->grantsAccess($employee)) {
                continue;
            }

            $members[$key][] = $employee->id;

            if (! isset($names[$key]) && $employee->departmentName !== null) {
                $names[$key] = $employee->departmentName;
            }
        }

        foreach ($names as $key => $name) {
            yield new DirectoryGroupSnapshot(HrisDirectorySync::DEPARTMENT_PREFIX.$key, $name, $members[$key] ?? []);
        }
    }

    public function verify(array $credentials): bool
    {
        try {
            $this->probe($credentials);

            return true;
        } catch (DirectoryConnectionFailed) {
            return false;
        }
    }

    public function supportsIncremental(): bool
    {
        return false;
    }

    /** The provider's name, as messages and the catalogue use it. */
    protected function name(): string
    {
        return $this->provider()->label();
    }

    protected function http(): HrisHttp
    {
        return new HrisHttp($this->name());
    }

    protected function failure(string $reason): DirectoryConnectionFailed
    {
        return DirectoryConnectionFailed::make($this->name(), $reason);
    }

    /**
     * A required credential, or the refusal that names it.
     *
     * @param  array<string, mixed>  $credentials
     *
     * @throws DirectoryConnectionFailed
     */
    protected function credential(array $credentials, string $key): string
    {
        $value = $credentials[$key] ?? null;

        if (! is_string($value) || trim($value) === '') {
            throw $this->failure("Missing credential: {$key}.");
        }

        return trim($value);
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    protected function optional(array $credentials, string $key): ?string
    {
        $value = $credentials[$key] ?? null;

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    /**
     * A continuation URL read from a RESPONSE BODY, kept only if it stays on the provider's
     * own base — it is followed carrying the customer's credentials, so a body that ever
     * named another host must not be able to send them there (the same pin the Entra
     * connector puts on `@odata.nextLink`).
     */
    protected function pinned(mixed $next, string $base): ?string
    {
        if (! is_string($next) || $next === '') {
            return null;
        }

        return str_starts_with($next, rtrim($base, '/').'/') ? $next : null;
    }
}
