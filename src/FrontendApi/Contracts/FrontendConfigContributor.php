<?php

declare(strict_types=1);

namespace Cbox\Id\FrontendApi\Contracts;

/**
 * Something that adds to the public configuration a browser reads before it draws a
 * sign-in box.
 *
 * THE FRAMEWORK DOES NOT KNOW ABOUT BRANDING, and should not learn. Appearance lives in
 * the application — a customer's palette, their corner radius, their logo — and the
 * framework owning a channel does not make it the right place to own what travels over
 * it. So the config document is assembled from the framework's own facts (who the issuer
 * is, which endpoints exist, which sign-in methods are on) and then handed to whatever
 * has registered here.
 *
 * EVERYTHING CONTRIBUTED IS PUBLIC. This document is fetched by an anonymous browser
 * holding only a publishable key, so a contributor that adds anything conditioned on who
 * is asking has misunderstood the channel — nobody is asking yet. That is the whole
 * question a contributor must answer before adding a field: would I put this in the page
 * source?
 */
interface FrontendConfigContributor
{
    /**
     * Merge this contributor's fields into the document.
     *
     * @param  array<string, mixed>  $config
     * @return array<string, mixed>
     */
    public function contribute(array $config): array;
}
