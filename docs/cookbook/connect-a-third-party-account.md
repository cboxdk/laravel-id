---
title: Connect a person's third-party account
description: Configure a GitHub pipe, connect a signed-in person's GitHub account, and lease their token from your app to call the GitHub API
weight: 41
---

# Connect a person's third-party account

Let a signed-in person connect their GitHub account, then call the GitHub API as them from
your app — without your app ever storing a GitHub token. Everything runs inside an
[environment](../core-concepts/environments.md). See [Pipes](../core-concepts/pipes.md)
for the model.

## 1. Configure the pipe

Create an OAuth App on GitHub (Settings › Developer settings › OAuth Apps) with your
callback URL, then:

```php
use Cbox\Id\Pipes\Contracts\Pipes;

$pipe = app(Pipes::class)->configure('github', $githubClientId, $githubClientSecret, ['read:user', 'repo']);
app(Pipes::class)->grant($pipe->id, $yourAppsClientId);
```

## 2. Connect the account

```php
use Cbox\Id\Pipes\Contracts\PipeConnections;
use Cbox\Id\Pipes\Exceptions\PipeConnectFailed;
use Cbox\Id\Pipes\ValueObjects\PipeConnectState;

Route::get('/account/pipes/github/connect', function () {
    $authorization = app(PipeConnections::class)->start('github', auth()->id(), url('/account/pipes/github/callback'));
    session()->put('pipes:github', $authorization->state->toArray());

    return redirect()->away($authorization->url);
});

Route::get('/account/pipes/github/callback', function (Request $request) {
    $flow = PipeConnectState::fromMixed(session()->pull('pipes:github'));

    if ($flow === null || $flow->userId !== (string) auth()->id() || $request->filled('error')) {
        return redirect('/account')->with('error', 'GitHub was not connected.');
    }

    try {
        app(PipeConnections::class)->complete($flow, (string) $request->query('state'), (string) $request->query('code'));
    } catch (PipeConnectFailed $e) {
        return redirect('/account')->with('error', 'GitHub was not connected ('.$e->reason.').');
    }

    return redirect('/account')->with('status', 'GitHub connected.');
});
```

## 3. Lease a token and call the API

```php
use Cbox\Id\Pipes\Contracts\PipeTokens;
use Cbox\Id\Pipes\Exceptions\PipeConnectionMissing;
use Cbox\Id\Pipes\Exceptions\PipeReauthorizationRequired;

try {
    $token = app(PipeTokens::class)->lease('github', $userId, $yourAppsClientId, 'list-repos');
} catch (PipeConnectionMissing|PipeReauthorizationRequired) {
    return redirect('/account/pipes/github/connect');
}

$repos = Http::withToken($token->accessToken)
    ->withHeaders(['Accept' => 'application/vnd.github+json'])
    ->get('https://api.github.com/user/repos')
    ->json();
```

Drop the token when you are done; ask again next time. The lease refreshes it when it has
to.

## 4. Run the scheduler

`cbox-id:pipes:refresh` keeps tokens fresh and finds dead connections early. It is
registered on the scheduler — see [Background work](../operations/background-work.md).
