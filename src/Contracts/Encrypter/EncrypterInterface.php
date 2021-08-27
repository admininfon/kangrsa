<?php
/*
 * This file is part of KangST.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace KangRSA\Contracts\Encrypter;


interface EncrypterInterface
{
    /**
     * Encrypt the given value.
     *
     * @param  mixed  $value
     * @param  bool  $serialize
     * @return string
     *
     * @throws \Exception
     */
    public function encrypt($value, $serialize = false);

    /**
     * Decrypt the given value.
     *
     * @param  string  $payload
     * @param  string  $iv
     * @param  bool  $unserialize
     * @return mixed
     *
     * @throws \Exception
     */
    public function decrypt($payload, $iv, $unserialize = false);
}
