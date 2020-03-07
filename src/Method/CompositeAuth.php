<?php
declare(strict_types=1);

namespace Lengbin\Auth\Method;

use Lengbin\Auth\IdentityRepositoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Lengbin\Auth\AuthInterface;
use Lengbin\Auth\IdentityInterface;

/**
 * CompositeAuth allows multiple authentication methods at the same time.
 *
 * The authentication methods contained by CompositeAuth are configured via {@see setAuthMethods()},
 * which is a list of supported authentication class configurations.
 */
final class CompositeAuth implements AuthInterface
{
    /**
     * @var AuthInterface[]
     */
    private $authMethods = [];
    /**
     * @var IdentityRepositoryInterface
     */
    protected $identityRepository;

    public function __construct(IdentityRepositoryInterface $identityRepository)
    {
        $this->identityRepository = $identityRepository;
    }

    /**
     * 设置 获得参数名称
     * @param string|null $name
     *
     * @return mixed
     */
    public function setName(string $name)
    {

    }

    public function authenticate(ServerRequestInterface $request): ?IdentityInterface
    {
        foreach ($this->authMethods as $i => $class) {
            if (!$class instanceof AuthInterface) {
                $this->authMethods[$i] = $auth = new $class($this->identityRepository);
                if (!$auth instanceof AuthInterface) {
                    throw new \RuntimeException(get_class($class) . ' must implement ' . AuthInterface::class);
                }
            }
            if (is_string($i)) {
                $this->authMethods[$i]->setName($i);
            }
            $identity = $this->authMethods[$i]->authenticate($request);
            if ($identity !== null) {
                return $identity;
            }
        }

        return null;
    }

    public function challenge(ResponseInterface $response): ResponseInterface
    {
        foreach ($this->authMethods as $method) {
            $response = $method->challenge($response);
        }
        return $response;
    }

    public function setAuthMethods(array $methods): void
    {
        $this->authMethods = $methods;
    }
}
