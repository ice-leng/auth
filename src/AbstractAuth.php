<?php
declare(strict_types=1);

namespace Lengbin\Auth;

use Lengbin\Auth\Exception\InvalidArgumentException;
use Lengbin\Auth\Method\CompositeAuth;
use Lengbin\Auth\User\GuestIdentity;
use Lengbin\Auth\User\User;
use Lengbin\Helper\YiiSoft\Arrays\ArrayHelper;
use Lengbin\Auth\Exception\InvalidTokenException;
use Lengbin\Helper\YiiSoft\StringHelper;
use Psr\Container\ContainerInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class AuthMiddleware
 * thanks yii
 * @package Common\middleware\auth
 */
abstract class AbstractAuth
{

    protected const REQUEST_NAME = 'auth';

    protected $requestName;

    /**
     * @var ContainerInterface
     */
    public $container;

    /**
     * @var EventDispatcherInterface
     */
    public $eventDispatcher;

    public function __construct(ContainerInterface $container, EventDispatcherInterface $eventDispatcher)
    {
        $this->container = $container;
        $this->eventDispatcher = $eventDispatcher;
        $this->setRequestName(ArrayHelper::getValue($this->getConfig(), 'requestName', self::REQUEST_NAME));
    }

    /**
     * request name
     *
     * @param string $name
     */
    public function setRequestName(string $name): void
    {
        $this->requestName = $name;
    }

    /**
     * 配置
     * @return mixed
     */
    abstract public function getConfig(): array;

    /**
     * get identity class
     * @return mixed
     */
    public function getIdentityClass(): IdentityRepositoryInterface
    {
        $class = ArrayHelper::getValue($this->getConfig(), 'identityClass');
        if ($class === null) {
            throw new InvalidArgumentException('Please set auth config identityClass params');
        }
        $model = new $class;
        if (!$model instanceof IdentityRepositoryInterface) {
            throw new InvalidArgumentException($class . ' must implement ' . IdentityRepositoryInterface::class);
        }
        return $model;
    }

    /**
     * @return AuthInterface
     */
    public function getAuthenticator(IdentityRepositoryInterface $identityRepository): AuthInterface
    {
        $method = ArrayHelper::getValue($this->getConfig(), 'method');
        if ($method === null) {
            throw new InvalidArgumentException('Please set auth config method params');
        }

        if (is_array($method)) {
            $authenticator = new CompositeAuth($identityRepository);
            $authenticator->setAuthMethods($method);
        } else {
            $authenticator = new $method($identityRepository);
            if (!$authenticator instanceof AuthInterface) {
                throw new InvalidArgumentException(get_class($authenticator) . ' must implement ' . AuthInterface::class);
            }
        }
        return $authenticator;
    }

    /**
     * check url path
     *
     * @param string $path
     * @param array  $patterns
     *
     * @return bool
     */
    public function checkPath($path, array $patterns = []): bool
    {
        $status = false;
        foreach ($patterns as $pattern) {
            if (StringHelper::matchWildcard($pattern, $path)) {
                $status = true;
                break;
            }
        }
        return $status;
    }

    /**
     * @param string $path
     *
     * @return bool
     */
    public function checkPublicList($path)
    {
        $publicList = ArrayHelper::getValue($this->getConfig(), 'public', []);
        return $this->checkPath($path, $publicList);
    }

    /**
     * @param $path
     *
     * @return bool
     */
    public function checkWhitelist($path)
    {
        $whitelist = ArrayHelper::getValue($this->getConfig(), 'whitelist', []);
        return $this->checkPath($path, $whitelist);
    }

    /**
     * get user
     *
     * @param ServerRequestInterface $request
     * @param null                   $isPublic
     * @param null                   $isWhitelist
     *
     * @return User
     * @throws InvalidTokenException
     */
    public function getUser(ServerRequestInterface $request, $isPublic = null, $isWhitelist = null): User
    {
        $guestIdentity = new GuestIdentity();
        $identityClass = $this->getIdentityClass();
        $user = new User($identityClass, $this->eventDispatcher);
        $user->setIdentity($guestIdentity);
        if ($isPublic) {
            return $user;
        }
        $identity = $this->getAuthenticator($identityClass)->authenticate($request) ?? $guestIdentity;
        $user->login($identity);
        if (!$isWhitelist && !$identity->getId()) {
            throw new InvalidTokenException();
        }
        return $user;
    }
}
