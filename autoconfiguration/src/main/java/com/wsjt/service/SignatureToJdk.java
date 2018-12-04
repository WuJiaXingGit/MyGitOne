package com.wsjt.service;

import java.util.Map;

public interface SignatureToJdk {

    /**
     * @return 获取公钥和私钥
     */
    Map<String, ?> generateKey();

    /**
     * 获取签名
     *
     * @param src        要签名的内容
     * @param privateKey 私钥
     * @return 签名后的内容
     */
    String getSignature(String src, byte[] privateKey);

    /**
     * 验证签名
     *
     * @param src       签名前的内容
     * @param result    签名后的内容
     * @param publicKey 公钥
     * @return 签名是否正确
     */
    boolean verifySignature(String src, String result, byte[] publicKey);
}
