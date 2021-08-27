<?php
/*
 * This file is part of KangST.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

require_once __DIR__.'/vendor/autoload.php';

// 数据载荷加载
$rsa_ser = \KangRSA\RSA\RSAService::make();
$rsa_ser->setDateSalt(); // 时间戳 自动获取当前
$rsa_ser->setTenantId('you tenant id'); // 编码
$rsa_ser->setJsonSalt('you json value on md5'); // json散列

// 以下选填
$rsa_ser->setSaltId('you pwd');   // 加密密钥
$rsa_ser->setSaltIv('you iv');   // 加密向量
$rsa_ser->setSaltHash('you hash type'); // 加密算法

// 使用加密时 参数填 true
$rsa_ser->setStrictVerify(false); // 加密是否

// RSA数据加密
$rsa = \KangRSA\Support\RSACrypter::make($options = array(
    'public_key' => __DIR__ . '/pub.key',
    'private_key' => __DIR__ . '/pri.key',
));
echo var_export($options, true), PHP_EOL;

$cipher_text = $rsa->encode($payload = $rsa_ser->toToken());
echo $payload, PHP_EOL;
echo $cipher_text, PHP_EOL;

// 我的密钥有密码验证
$rsa->setPassphrase('kst0318');
$cipher_data = $rsa->decode($cipher_text, $rsa::CRYPT_KEY_PRIVATE);
echo $cipher_data, PHP_EOL;