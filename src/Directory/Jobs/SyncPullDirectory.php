<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Jobs;

use Cbox\Id\Directory\DirectoryPullSync;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;

/**
 * Pull one directory now, on a worker — "sync now" from a console, and the first sync of a
 * newly connected HR system, which can be thousands of people and has no business running
 * inside the request that connected it.
 *
 * Carries the directory's id and nothing else: never the model, never the credentials. The
 * directory is resolved across the environment boundary only to learn which environment it
 * lives in; {@see DirectoryPullSync} re-enters that environment before it reads or writes.
 *
 * Unique per directory while queued, and the sync itself holds a per-directory lock while
 * it runs, so a double click and the scheduler meeting a "sync now" run it once. A failed
 * pull is recorded on the directory by the sync and is not retried here: the schedule is
 * the retry.
 */
class SyncPullDirectory implements ShouldBeUnique, ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;

    public int $tries = 1;

    public function __construct(
        public readonly string $directoryId,
        public readonly bool $full = false,
    ) {}

    public function uniqueId(): string
    {
        return $this->directoryId;
    }

    public function handle(EnvironmentContext $context, DirectoryPullSync $sync): void
    {
        $directory = $context->withoutScope(
            fn (): ?Directory => Directory::query()->whereKey($this->directoryId)->first(),
        );

        if ($directory === null || ! $directory->provider->isPull()) {
            return;
        }

        try {
            $sync->sync($directory, $this->full);
        } catch (DirectoryConnectionFailed) {
            // Recorded on the directory (or another run holds it); nothing for a worker to add.
        }
    }
}
