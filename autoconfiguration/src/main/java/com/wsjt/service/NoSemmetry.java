package com.wsjt.service;

import org.springframework.lang.NonNull;

import javax.crypto.SecretKey;
import java.util.Map;

public interface NoSemmetry {

    /**
     * 获取公钥和私钥
     *
     * @return 公钥和私钥的集合
     */
    Map<String, ?> generateKeyPair();

    /**
     * 根据对方的公钥生成自己的密钥对
     *
     * @param publicKey 对方的公钥
     * @return 公钥和私钥的集合
     */
    default Map<String, ?> generateKeyPair(byte[] publicKey) {
        return null;
    }

    /**
     * 根据对方的公钥和自己的私钥生成本地密钥的对象
     *
     * @param publicKey  对方的公钥
     * @param privateKey 自己的私钥
     * @return 本地密钥对象
     */
    default SecretKey getSecretKey(byte[] publicKey, byte[] privateKey) {
        return null;
    }

    ;


    /**
     * 根据对方的公钥和自己的私钥生成本地密钥的对象数组
     *
     * @param publicKey  对方的公钥
     * @param privateKey 自己的私钥
     * @return 本地密钥对象数组
     */
    default byte[] getSecretKeyBytes(byte[] publicKey, byte[] privateKey) {
        return null;
    }

    ;

    /**
     * 加密数据
     *
     * @param src        需要加密的数据
     * @param publicKey  对方的公钥
     * @param privateKey 自己的私钥
     * @return 加密后的数据
     */
    default String encrypt(@NonNull String src, byte[] publicKey, byte[] privateKey) {
        return null;
    }

    ;

    /**
     * RSA加密
     *
     * @param publicKey 公钥
     * @return 解密后的数据
     */
    default String pulbicKeyEncrypt(String src, byte[] publicKey) {
        return null;
    }

    /**
     * RAS加密
     *
     * @param privateKey 私钥
     * @return 解密后数据
     */

    default String privateKeyEncrypt(String src, byte[] privateKey) {
        return null;
    }

    /**
     * 解密数据
     *
     * @param src        待解密的数据
     * @param publicKey  对方的公钥
     * @param privateKey 自己私钥
     * @return
     */
    default String decrypt(@NonNull String src, byte[] publicKey, byte[] privateKey) {
        return null;
    }

    ;

    /**
     * RSA解密
     *
     * @param publicKey 公钥
     * @return 解密后的数据
     */
    default String pulbicKeyDecrypt(String src, byte[] publicKey) {
        return null;
    }

    /**
     * RAS解密
     *
     * @param privateKey 私钥
     * @return 解密后数据
     */

    default String privateKeyDecrypt(String src, byte[] privateKey) {
        return null;
    }


}
