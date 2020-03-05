<?php

declare(strict_types=1);

namespace Lengbin\Auth\User;

use Lengbin\Auth\IdentityInterface;

class GuestIdentity implements IdentityInterface
{
    public function getId(): ?string
    {
        return null;
    }
}
