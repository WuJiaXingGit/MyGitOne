package com.wsjt.service;

import java.io.IOException;
import java.security.Key;
import java.util.Map;

/**
 * 需要加密和解密的公共接口,需要时只需导入合适的实现类
 */
public interface Semmetry {


    /**
     * this method 用于加密
     *
     * @param src 需要加密的数据
     * @param key 密钥
     * @return 已加密的数据
     */
    String encrypt(String src, Key key);

    /**
     * this method 用于加密
     *
     * @param src 需要加密的数据
     * @param key 密钥
     * @return 已加密的数据
     */
    String encrypt(byte[] src, Key key);

    /**
     * method 用于PBE加密
     *
     * @param src  要加密的数据
     * @param key  密钥
     * @param salt 盐
     * @return
     */
    default String encrypt(String src, Key key, byte[] salt) {
        return null;
    }

    /**
     * this method 用于解密
     *
     * @param src 需要解密的数据
     * @param key 密钥
     * @return 已解密的 数据
     */
    String decrypt(String src, Key key) throws IOException;

    /**
     * this method 用于解密
     *
     * @param src 需要解密的数据
     * @param key 密钥
     * @return 已解密的 数据
     */
    String decrypt(byte[] src, Key key);

    /**
     * 用于PBE解密
     *
     * @param src  需要解密的数据
     * @param key  密钥
     * @param salt 盐
     * @return
     */
    default String decrypt(String src, Key key, byte[] salt) {
        return null;
    }


    /**
     * 用于对称加密
     *
     * @return 返回的时密钥, 加密和解密需要同一把密钥, 应由用户保管
     */
    Key generateKey();

    /**
     * 获盐
     *
     * @param numBytes 设置盐的长度,必须为八个字字节
     * @return
     */
    default byte[] secureRandom(int numBytes) {
        return null;
    }

    ;
}
