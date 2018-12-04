package com.wsjt.service.Impl;

import com.wsjt.service.NoSemmetryProperties;
import lombok.Getter;
import lombok.Setter;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;


public class KeyUtils {

    private static NoSemmetryProperties sp;

    public static void setSp(NoSemmetryProperties sp) {
        KeyUtils.sp = sp;
    }

    /**
     * 获取公钥数组
     *
     * @param map 由公钥的集合
     * @return 公钥的数组
     */
    public static byte[] getDHPublicKey(Map<String, ?> map) {
        DHPublicKey dhPublicKey = (DHPublicKey) map.get(sp.getDhPublicKeyName());
        return dhPublicKey.getEncoded();
    }

    /**
     * 获取私钥的数组
     *
     * @param map 用私钥的集合
     * @return 私钥数组
     */
    public static byte[] getDHPrivateKey(Map<String, ?> map) {
        DHPrivateKey dhPrivateKey = (DHPrivateKey) map.get(sp.getDhPrivateKeyName());
        return dhPrivateKey.getEncoded();
    }

    /**
     * 获取公钥数组
     *
     * @param map 由公钥的集合
     * @return 公钥的数组
     */
    public static byte[] getRSAPublicKey(Map<String, ?> map) {
        RSAPublicKey dhPublicKey = (RSAPublicKey) map.get(sp.getRsaPublicKeyName());
        return dhPublicKey.getEncoded();
    }

    /**
     * 获取私钥的数组
     *
     * @param map 用私钥的集合
     * @return 私钥数组
     */
    public static byte[] getRSAPrivateKey(Map<String, ?> map) {
        RSAPrivateKey dhPrivateKey = (RSAPrivateKey) map.get(sp.getRsaPrivateKeyName());
        return dhPrivateKey.getEncoded();
    }

}
