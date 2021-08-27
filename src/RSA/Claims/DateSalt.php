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


/**
 * Class DateSalt
 *
 * 说明：时间戳参数文件
 * @package App\Services\RSA\Claims
 */
class DateSalt extends Claim
{
    protected $name = 'date_salt';

    /**
     * @inheritDoc
     */
    public function getValue()
    {
        return empty($this->value) ? time() : $this->value;
    }
}
