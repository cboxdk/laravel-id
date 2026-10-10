<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Testing;

use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\Hris\HrisConnector;
use Cbox\Id\Directory\Hris\ValueObjects\HrisDepartment;
use Cbox\Id\Directory\Hris\ValueObjects\HrisEmployee;
use Cbox\Id\Directory\Hris\ValueObjects\HrisSyncOptions;

/**
 * A controllable HR system for testing the HR-aware sync without a vendor's API: set the
 * employees and departments it returns, make it incremental, make it refuse — and read back
 * what the last pull asked it for ({@see self::$lastOptions}).
 *
 * In incremental mode it answers only the employees listed in {@see self::changed()} when
 * asked "changed since", which is what a real provider's filter does.
 */
class FakeHrisProvider extends HrisConnector
{
    public ?HrisSyncOptions $lastOptions = null;

    /** @var list<HrisEmployee>|null */
    private ?array $changed = null;

    private ?string $refusal = null;

    /**
     * @param  list<HrisEmployee>  $employees
     * @param  list<HrisDepartment>  $departments
     */
    public function __construct(
        private readonly DirectoryProvider $provider = DirectoryProvider::BambooHr,
        private array $employees = [],
        private array $departments = [],
        private readonly bool $incremental = false,
    ) {}

    /** @param  list<HrisEmployee>  $employees */
    public function returns(array $employees): self
    {
        $this->employees = $employees;

        return $this;
    }

    /** @param  list<HrisDepartment>  $departments */
    public function returnsDepartments(array $departments): self
    {
        $this->departments = $departments;

        return $this;
    }

    /**
     * What an incremental pull answers.
     *
     * @param  list<HrisEmployee>  $employees
     */
    public function changed(array $employees): self
    {
        $this->changed = $employees;

        return $this;
    }

    /** Make every request fail with this reason, as a refused or unreachable API would. */
    public function refuses(?string $reason): self
    {
        $this->refusal = $reason;

        return $this;
    }

    public function provider(): DirectoryProvider
    {
        return $this->provider;
    }

    public function supportsIncremental(): bool
    {
        return $this->incremental;
    }

    public function fetchEmployees(array $credentials, HrisSyncOptions $options): iterable
    {
        $this->lastOptions = $options;
        $this->refuse();

        return $options->changedSince !== null && $this->changed !== null ? $this->changed : $this->employees;
    }

    public function fetchDepartments(array $credentials, HrisSyncOptions $options): iterable
    {
        $this->refuse();

        return $this->departments;
    }

    public function probe(array $credentials): void
    {
        $this->refuse();
    }

    private function refuse(): void
    {
        if ($this->refusal !== null) {
            throw DirectoryConnectionFailed::make($this->provider->label(), $this->refusal);
        }
    }
}
