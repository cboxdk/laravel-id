<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Support;

/**
 * How a {@see ScimQueryAttribute} is answered in SQL.
 */
enum ScimQueryAttributeKind
{
    /** A real column, or a path inside the stored `resource` JSON. */
    case Column;

    /**
     * A value every stored element has by definition — the one stored email IS the
     * primary, work address — so a comparison against it is decided in PHP and only
     * the element's presence is asked of the database.
     */
    case Constant;

    /** A multi-valued attribute held in another table (a group's `members`). */
    case Relation;
}
