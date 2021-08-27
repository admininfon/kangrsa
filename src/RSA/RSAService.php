<?php
/*
 * This file is part of KangST.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace KangRSA\RSA;


use KangRSA\RSA\Claims\DateSalt;
use KangRSA\RSA\Claims\JsonSalt;
use KangRSA\RSA\Claims\SaltHash;
use KangRSA\RSA\Claims\SaltId;
use KangRSA\RSA\Claims\SaltIv;
use KangRSA\RSA\Claims\TenantId;

class RSAService
{
    /**
     * payload
     *
     * @var PayloadManager
     */
    private $payload;
    /**
     * allowed_payload_keys
     *
     * @var \string[][]
     */
    private $allowed_payload_keys = [
        DateSalt::class => ['name' => DateSalt::class, 'value' => ''],
        JsonSalt::class => ['name' => JsonSalt::class, 'value' => ''],
        SaltHash::class => ['name' => SaltHash::class, 'value' => ''],
        SaltId::class   => ['name' => SaltId::class, 'value' => ''],
        TenantId::class => ['name' => TenantId::class, 'value' => ''],
        SaltIv::class   => ['name' => SaltIv::class, 'value' => ''],
    ];

    /**
     * 构建加密数据
     *
     * @param array $options [optional] 配置参数 <p>
     * Params format: <pre>array (
     *  'DateSalt' => '当前时间戳',
     *  'JsonSalt' => '加密数据',
     *  'SaltHash' => '加密算法',
     *  'SaltId' => '加密密钥',
     *  'TenantId' => 'tenant_id',
     *  'SaltIv' => '加密向量',
     * )</pre>
     * 顺序可改变
     * </p>
     * @return RSAService
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-17 10:52:38
     */
    public static function make(array $options = array())
    {
        return new self($options);
    }

    /**
     * RSAService constructor.
     *
     * @param array $options [optional] 配置参数
     */
    private function __construct(array $options = array())
    {
        foreach ($options as $key => $value) {
            switch (strtolower($key)) {
                case 'datesalt':
                    $this->setDateSalt($value);
                    break;
                case 'jsonsalt':
                    $this->setJsonSalt($value);
                    break;
                case 'salthash':
                    $this->setSaltHash($value);
                    break;
                case 'saltid':
                    $this->setSaltId($value);
                    break;
                case 'tenantid':
                    $this->setTenantId($value);
                    break;
                case 'saltiv':
                    $this->setSaltIv($value);
                    break;
            }
        }

        $this->payload = new PayloadManager;
    }

    /**
     * formatPayload
     *
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-17 10:52:44
     */
    private function formatPayload()
    {
        $format = array();
        foreach ($this->allowed_payload_keys as $key => $item) {
            $format[$key] = new $item['name']($item['value']);
        }

        $format_payloads[] = $format[TenantId::class]->getValue();
        $salt_id = $format[SaltId::class]->getValue();
        $salt_iv = $format[SaltIv::class]->getValue();
        if (!empty($salt_id) && !empty($salt_iv)) {
            $format_payloads[] = $salt_id . '#' . $salt_iv;
        } else {
            $format_payloads[] = null;
        }
        $format_payloads[] = $format[SaltHash::class]->getValue();
        $format_payloads[] = $format[JsonSalt::class]->getValue();
        $format_payloads[] = $format[DateSalt::class]->getValue();

        $this->payload->setPayload(implode(':', $format_payloads));
    }

    /**
     * setTenantId
     *
     * @param null $value
     * @return $this
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-17 10:35:44
     */
    public function setTenantId($value = null): RSAService
    {
        $this->allowed_payload_keys[TenantId::class]['value'] = $value;

        return $this;
    }

    /**
     * setSaltId
     *
     * @param null $value
     * @return $this
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-17 10:35:40
     */
    public function setSaltId($value = null): RSAService
    {
        $this->allowed_payload_keys[SaltId::class]['value'] = $value;

        return $this;
    }

    /**
     * setSaltHash
     *
     * @param null $value
     * @return $this
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-17 10:35:35
     */
    public function setSaltHash($value = null): RSAService
    {
        $this->allowed_payload_keys[SaltHash::class]['value'] = $value;

        return $this;
    }

    /**
     * setJsonSalt
     *
     * @param null $value
     * @return $this
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-17 10:35:30
     */
    public function setJsonSalt($value = null): RSAService
    {
        $this->allowed_payload_keys[JsonSalt::class]['value'] = $value;

        return $this;
    }

    /**
     * setDateSalt
     *
     * @param null $value
     * @return $this
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-17 10:35:19
     */
    public function setDateSalt($value = null): RSAService
    {
        $this->allowed_payload_keys[DateSalt::class]['value'] = $value;

        return $this;
    }

    /**
     * setSaltIv
     *
     * @param null $value
     * @return $this
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-17 10:53:32
     */
    public function setSaltIv($value = null): RSAService
    {
        $this->allowed_payload_keys[SaltIv::class]['value'] = $value;

        return $this;
    }

    /**
     * 修改严格效验
     *
     * @param bool $type
     * @return $this
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-19 15:49:34
     */
    public function setStrictVerify(bool $type = true): RSAService
    {
        $this->payload->setStrictVerify($type);

        return $this;
    }

    /**
     * Get payload string.
     *
     * @return string
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-17 10:12:59
     */
    public function toToken(): string
    {
        $this->formatPayload();

        return (string)$this->payload;
    }
}
