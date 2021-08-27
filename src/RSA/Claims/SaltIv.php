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
 * Class SaltIv
 *
 * 说明：加密向量文件
 * @package App\Services\RSA\Claims
 */
class SaltIv extends Claim
{
    protected $name = 'iv';
}
