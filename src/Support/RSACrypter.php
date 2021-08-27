<?php
/*
 * This file is part of KangST.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace KangRSA\Support;


class RSACrypter
{
    const CRYPT_KEY_PUBLIC = 0; // 公钥使用
    const CRYPT_KEY_PRIVATE = 1; // 私钥使用

    public $public_key = null; // 公钥
    public $private_key = null; // 私钥
    private $passphrase;

    // base64 字符过滤
    private $base64_replace = array('+' => '*', '/' => '-', '=' => '_');

    /**
     * 构建RSA加密对象
     *
     * ```array
     * Example $options:
     * [
     * 'public_key' => 'path or content'
     * 'private_key' => 'path or content'
     * ]
     * ```
     *
     * @param array $options [optional] 配置参数
     * @return RSACrypter
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-17 10:05:51
     */
    public static function make(array $options = array()): RSACrypter
    {
        return new self($options);
    }

    /**
     * RSACrypter constructor.
     *
     * ```array
     * Example $options:
     * [
     * 'public_key' => 'path or content'
     * 'private_key' => 'path or content'
     * ]
     * ```
     *
     * @param array $options [optional] 配置参数
     */
    private function __construct(array $options = array())
    {
        if (!empty($options['public_key'])) {
            $this->public_key = file_exists($options['public_key']) ? (file_get_contents($options['public_key'])) : $options['public_key'];
        }

        if (!empty($options['private_key'])) {
            $this->private_key = file_exists($options['private_key']) ? (file_get_contents($options['private_key'])) : $options['private_key'];
        }
    }

    /**
     * 加密数据
     *
     * @param $value
     * @param int $crypt_key_type
     * @return array|string|string[]
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-17 09:57:00
     * @throws \Exception
     */
    public function encode($value, int $crypt_key_type = self::CRYPT_KEY_PUBLIC)
    {
        // 加密类型
        switch ($crypt_key_type) {
            case self::CRYPT_KEY_PUBLIC:
                if (!\openssl_public_encrypt($value, $crypted, $this->verifyPUKey())) {
                    trigger_error(openssl_error_string(), E_USER_ERROR);
                }
                break;

            case self::CRYPT_KEY_PRIVATE:
                if (!\openssl_private_encrypt($value, $crypted, $this->verifyPRKey())) {
                    trigger_error(openssl_error_string(), E_USER_ERROR);
                }
                break;
        }

        return $this->base64Encode($crypted);
    }

    /**
     * 解密数据
     *
     * @param $payload
     * @param int $crypt_key_type
     * @return mixed
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-17 09:57:14
     * @throws \Exception
     */
    public function decode($payload, int $crypt_key_type = self::CRYPT_KEY_PUBLIC)
    {
        $payload = $this->base64Decode($payload);
        // 解密类型
        switch ($crypt_key_type) {
            case self::CRYPT_KEY_PUBLIC:
                if (!\openssl_public_decrypt($payload, $decrypted, $this->verifyPUKey())) {
                    trigger_error(openssl_error_string(), E_USER_ERROR);
                }
                break;

            case self::CRYPT_KEY_PRIVATE:
                if (!\openssl_private_decrypt($payload, $decrypted, $this->verifyPRKey())) {
                    trigger_error(openssl_error_string(), E_USER_ERROR);
                }
                break;
        }

        return $decrypted;
    }

    /**
     * verifyPUKey
     *
     * @return resource
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-16 19:59:56
     */
    public function verifyPUKey()
    {
        if (!empty($this->public_key) && $pukey = openssl_get_publickey($this->public_key)) {
            return $pukey;
        }
        throw new \InvalidArgumentException('Invalid public key');
    }

    /**
     * verifyPRKey
     *
     * @return resource
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-16 20:00:00
     */
    public function verifyPRKey()
    {
        if (!empty($this->private_key) && $prkey = openssl_get_privatekey($this->private_key, $this->passphrase)) {
            return $prkey;
        }
        throw new \InvalidArgumentException('Invalid Private key');
    }

    /**
     * base64Encode
     *
     * @param string $string
     * @return string
     * @throws \Exception
     */
    private function base64Encode(string $string): string
    {
        if (!$base64 = base64_encode($string)) {
            throw new \Exception('base64 encode error');
        }

        return str_replace(array_keys($this->base64_replace), array_values($this->base64_replace), $base64);
    }

    /**
     * base64Decode
     *
     * @param string $base64
     * @return string
     * @throws \Exception
     */
    private function base64Decode(string $base64): string
    {
        $string = str_replace(array_values($this->base64_replace), array_keys($this->base64_replace), $base64);
        if (!$result = base64_decode($string)) {
            throw new \Exception('base64 decode error');
        }

        return $result;
    }

    /**
     * @param false|mixed|string|null $private_key
     */
    public function setPrivateKey($private_key): RSACrypter
    {
        $this->private_key = $private_key;
        return $this;
    }

    /**
     * @param false|mixed|string|null $public_key
     */
    public function setPublicKey($public_key): RSACrypter
    {
        $this->public_key = $public_key;
        return $this;
    }

    /**
     * The hash private key password
     *
     * @param null|string $passphrase
     * @return RSACrypter
     */
    public function setPassphrase(?string $passphrase): RSACrypter
    {
        $this->passphrase = $passphrase;
        return $this;
    }
}
