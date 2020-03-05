<?php

declare(strict_types=1);

namespace Lengbin\Auth\User\Event;

use Lengbin\Auth\IdentityInterface;

class BeforeLogout
{
    private $identity;
    private $isValid = true;

    public function __construct(IdentityInterface $identity)
    {
        $this->identity = $identity;
    }

    public function invalidate(): void
    {
        $this->isValid = false;
    }

    public function isValid(): bool
    {
        return $this->isValid;
    }

    public function getIdentity(): IdentityInterface
    {
        return $this->identity;
    }
}
