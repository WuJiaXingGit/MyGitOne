package com.wsjt.service.Impl;

import com.wsjt.service.Semmetry;
import com.wsjt.service.SemmetryProperties;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * 在3des基础上更安全
 * author 吴家兴
 */
@Getter
@Setter
public class AesSemmetryToJdk implements Semmetry {


    private final Logger logger = LoggerFactory.getLogger(AesSemmetryToJdk.class);
    private SemmetryProperties sp;

    @Override
    public String encrypt(String src, Key key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] bytes = cipher.doFinal(src.getBytes());
            String result = sp.getBe().encode(bytes);
            return result;
        } catch (NoSuchAlgorithmException e) {
            logger.trace("没有这样的算法", e);
        } catch (NoSuchPaddingException e) {
            logger.trace("没有这样的填充", e);
        } catch (InvalidKeyException e) {
            logger.trace("无效的key", e);
        } catch (BadPaddingException e) {
            logger.trace("无效的填充", e);
        } catch (IllegalBlockSizeException e) {
            logger.trace("非法块大小", e);
        }
        return null;
    }

    @Override
    public String encrypt(byte[] src, Key key) {
        return encrypt(new String(src), key);
    }

    @Override
    public String decrypt(String src, Key key) throws IOException {
        return decrypt(sp.getDe().decodeBuffer(src), key);
    }

    @Override
    public String decrypt(byte[] src, Key key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] bytes1 = cipher.doFinal(src);
            return new String(bytes1);

        } catch (NoSuchAlgorithmException e) {
            logger.trace("没有这样的算法", e);
        } catch (NoSuchPaddingException e) {
            logger.trace("没有这样的填充", e);
        } catch (InvalidKeyException e) {
            logger.trace("无效的key", e);
        } catch (BadPaddingException e) {
            logger.trace("无效的填充", e);
        } catch (IllegalBlockSizeException e) {
            logger.trace("非法块大小", e);
        }
        return null;
    }

    @Override
    public Key generateKey() {
        try {
            //生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES"); //创建密钥生成器
            keyGenerator.init(sp.getAesKeySize());//初始化生成器
            SecretKey secretKey = keyGenerator.generateKey(); //生成密钥
            byte[] encoded = secretKey.getEncoded();  //保存

            //key转换
            Key key = new SecretKeySpec(encoded, "AES");
            return key;
        } catch (NoSuchAlgorithmException e) {
            logger.trace("没有这样的算法", e);
        }
        return null;
    }

}
