<?php

declare(strict_types=1);

namespace Verdient\AliPay;

use Verdient\HttpAPI\AbstractClient;

/**
 * 支付宝
 * @author Verdient。
 */
class AliPay extends AbstractClient
{

    /**
     * @inheritdoc
     * @author Verdient。
     */
    public $protocol = 'https';

    /**
     * @inheritdoc
     * @author Verdient。
     */
    public $host = 'openapi.alipay.com';

    /**
     * @inheritdoc
     * @author Verdient。
     */
    public $routePrefix = 'v3';

    /**
     * @var string App 编号
     * @author Verdient。
     */
    public $appId;

    /**
     * @var string App 私钥
     * @author Verdient。
     */
    public $appPrivateKey;

    /**
     * @var string App 公钥
     * @author Verdient。
     */
    public $appPublicKey;

    /**
     * @var string App 加密秘钥
     * @author Verdient。
     */
    public $appEncryptKey;

    /**
     * @var string 公钥
     * @author Verdient。
     */
    public $publicKey;

    /**
     * @inheritdoc
     * @author Verdient。
     */
    public $request = Request::class;

    /**
     * @inheritdoc
     * @author Verdient。
     */
    public function request($path): Request
    {
        $request = new Request();
        $request->setUrl($this->getRequestPath() . '/' . $path);
        $request->appId  = $this->appId;
        $request->appPrivateKey  = $this->appPrivateKey;
        $request->appEncryptKey  = $this->appEncryptKey;
        $request->publicKey  = $this->publicKey;
        return $request;
    }
}
