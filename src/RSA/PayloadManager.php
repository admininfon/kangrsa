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


class PayloadManager
{
    /**
     * The payload.
     *
     * @var string $payload
     */
    private $payload;

    /**
     * The verify type.
     * @var bool $verify_type
     */
    private $verify_type;

    /**
     * Set the payload.
     *
     * @param mixed $payload
     */
    public function setPayload($payload): void
    {
        $this->payload = $payload;
    }

    /**
     * verify
     *
     * @return bool
     * @throws \InvalidArgumentException
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-16 19:46:16
     */
    public function verify(): bool
    {
        if (empty($this->payload)) {
            throw new \InvalidArgumentException('加密数据不能为空');
        }

        // 参数效验
        $load_data = explode(':', $this->payload) ?? array();
        if (!$load_data[0] || !$load_data[3] || !$load_data[4] || ($this->verify_type && (!$load_data[1] || !$load_data[2]))) {
            throw new \InvalidArgumentException('加密参数不是有效数据');
        }

        // 密钥效验
        if ($this->verify_type && !empty($load_data[1]) && !empty($load_data[2])) {
            if (!preg_match('/.+#/', $load_data[1])) {
                throw new \InvalidArgumentException('加密密钥不是有效数据');
            }
        }

        return true;
    }

    /**
     * setStrictVerify
     *
     * @param bool $type [optional] true:严格 false:宽松
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-19 15:39:12
     */
    public function setStrictVerify(bool $type = true)
    {
        $this->verify_type = $type;
    }

    /**
     * Get the payload.
     *
     * @return string
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-16 13:35:57
     */
    public function __toString()
    {
        $this->verify();

        return (string) $this->payload;
    }
}
