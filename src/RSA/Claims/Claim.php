<?php
/*
 * This file is part of KangST.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace KangRSA\RSA\Claims;


use KangRSA\Contracts\RSAs\Claim as ClaimContract;

abstract class Claim implements ClaimContract
{
    protected $name;
    protected $value;

    /**
     * Claim constructor.
     *
     * @param null|mixed $value
     */
    public function __construct($value = null)
    {
        if (!empty($value)) {
            $this->setValue($value);
        }
    }

    /**
     * Get the name.
     *
     * @return string
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-16 13:32:45
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * 负载数据效验
     *
     * @param $value
     * @return string
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-07-16 17:27:23
     */
    public function verify($value): string
    {
        if (preg_match('/(:|#)+/', $value)) {
            throw new \InvalidArgumentException('不是有效负载参数，参数内不能含有“:#”特殊符号');
        }

        return $value;
    }

    /**
     * Set the value.
     *
     * @param mixed $value
     * @return Claim
     */
    public function setValue($value): Claim
    {
        $this->verify($value);

        $this->value = $value;
        return $this;
    }

    /**
     * Get the value.
     * @return mixed
     */
    public function getValue()
    {
        return $this->value;
    }
}
