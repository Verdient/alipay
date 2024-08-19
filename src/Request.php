<?php

declare(strict_types=1);

namespace Verdient\AliPay;

use Exception;
use Verdient\http\Request as HttpRequest;
use Verdient\http\Response as HttpResponse;

/**
 * 请求
 * @author Verdient。
 */
class Request extends HttpRequest
{
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
    public function send(): Response
    {
        $parsedUrl = parse_url($this->getUrl());

        $timestamp = floor(microtime(true) * 1000);

        $authString = implode(',', [
            'app_id=' . $this->appId,
            'nonce=' . bin2hex(random_bytes(16)),
            'timestamp=' . $timestamp
        ]);

        $authContent = implode("\n", [
            $authString, $this->getMethod(), $parsedUrl['path'] . '?' . $parsedUrl['query'], '', ''
        ]);

        $privateKey =
            "-----BEGIN RSA PRIVATE KEY-----\n" .
            wordwrap($this->appPrivateKey, 64, "\n", true) .
            "\n-----END RSA PRIVATE KEY-----";

        openssl_sign($authContent, $sign, $privateKey, OPENSSL_ALGO_SHA256);

        $signature = base64_encode($sign);

        $this->addHeader('Alipay-Request-Id', md5(random_bytes(32)));
        $this->addHeader('Alipay-Encrypt-Type', 'AES');
        $this->addHeader('Authorization', 'ALIPAY-SHA256withRSA ' . $authString . ',sign=' . $signature);
        $this->addHeader('Content-Type', 'application/json');

        if (empty($this->appEncryptKey)) {
            return new Response(parent::send());
        }

        $res = parent::send();

        $statusCode = $res->getStatusCode();

        if ($statusCode < 200 || $statusCode > 299) {
            return new Response($res);
        }

        $headers = $res->getHeaders();

        $headers = array_change_key_case($res->getHeaders(), CASE_LOWER);

        if (!isset($headers['alipay-signature'])) {
            throw new Exception('Missing response header: alipay-signature');
        }

        $headerValues = [];

        $headerValues['alipay-signature'] = $headers['alipay-signature'];
        $headerValues['alipay-sn'] = $headers['alipay-sn'] ?? '';
        $headerValues['alipay-timestamp'] = $headers['alipay-timestamp'] ?? '';
        $headerValues['alipay-nonce'] = $headers['alipay-nonce'] ?? '';

        foreach ($headerValues as $name => $headerValue) {
            if (is_array($headerValue)) {
                if (empty($headerValue)) {
                    $headerValues[$name] = '';
                } else {
                    $headerValues[$name] = reset($headerValue);
                }
            }
        }


        $alipayPublicKey = "-----BEGIN PUBLIC KEY-----\n" .
            wordwrap($this->publicKey, 64, "\n", true) .
            "\n-----END PUBLIC KEY-----";

        $rawContent = $res->getRawContent();

        $verifyContent = $headerValues['alipay-timestamp'] . "\n"
            . $headerValues['alipay-nonce'] . "\n"
            . (empty($rawContent) ? "" : $rawContent) . "\n";

        if (openssl_verify($verifyContent, base64_decode($headerValues['alipay-signature']), $alipayPublicKey, OPENSSL_ALGO_SHA256) !== 1) {
            throw new Exception('signature verification failed');
        }

        $encryptKey = base64_decode($this->appEncryptKey);

        $iv = str_repeat("\0", 16);

        $rawContent = openssl_decrypt(base64_decode($rawContent), 'aes-128-cbc', $encryptKey, OPENSSL_NO_PADDING, $iv);

        $char = substr($rawContent, -1);

        $num = ord($char);

        if ($num != 62) {
            $rawContent = substr($rawContent, 0, -$num);
        }

        $status = $res->getHttpVersion() . ' ' . $res->getStatusCode() . ' ' . $res->getStatusMessage();

        $rawHeaders = str_replace(['Content-Type: text/plain', 'content-type: text/plain'], 'Content-Type: application/json', $res->getRawHeaders());

        $rawResponse = str_replace($res->getRawContent(), $rawContent, $res->getRawResponse());

        return new Response(new HttpResponse($res->getRequest(), $status, $rawHeaders, $rawContent, $rawResponse));
    }
}
