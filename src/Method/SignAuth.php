<?php

declare(strict_types=1);

namespace Lengbin\Auth\Method;

use Lengbin\Helper\YiiSoft\Arrays\ArrayHelper;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Lengbin\Auth\AuthInterface;
use Lengbin\Auth\IdentityInterface;

class SignAuth implements AuthInterface, IdentityInterface
{

    public $signParam = 'sign';
    public $timestampParam = 'timestamp';

    /**
     * Authenticates the current user.
     *
     * @param RequestInterface $request
     *
     * @return null|IdentityInterface
     */
    public function authenticate(ServerRequestInterface $request): ?IdentityInterface
    {
        $gets = $request->getQueryParams();
        $posts = $request->getParsedBody();
        $params = array_merge($gets, $posts);

        $secretKey = ArrayHelper::getValue($params, 'secretKey');
        if (is_null($secretKey)) {
            return $this;
        }

        $sign = ArrayHelper::remove($params, $this->signParam);
        $timestamp = ArrayHelper::remove($params, $this->timestampParam);

        //过滤掉为空的参数
        $filterParams = [];
        foreach ($params as $k => $v) {
            if (is_array($v)) {
                $v = json_encode($v, JSON_UNESCAPED_UNICODE);
            }
            if (trim($v) != '') {
                $filterParams[$k] = $v;
            }
        }

        ksort($filterParams);

        $str = http_build_query($filterParams);
        $str = urldecode($str);

        if ($str != '') {
            $str .= '&timestamp=' . $timestamp;
        } else {
            $str = 'timestamp=' . $timestamp;
        }

        $str .= '&key=' . $secretKey;

        $targetSign = md5($str);
        return $targetSign === $sign ? $this : null;
    }

    /**
     * Generates challenges upon authentication failure.
     * For example, some appropriate HTTP headers may be generated.
     *
     * @param ResponseInterface $response
     *
     * @return ResponseInterface
     */
    public function challenge(ResponseInterface $response): ResponseInterface
    {
        return $response;
    }

    /**
     * Returns an ID that can uniquely identify a user identity.
     * @return string an ID that uniquely identifies a user identity.
     */
    public function getId()
    {
        return 1;
    }
}
