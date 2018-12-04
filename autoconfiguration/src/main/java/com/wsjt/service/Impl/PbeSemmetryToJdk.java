package com.wsjt.service.Impl;

import com.wsjt.service.Semmetry;
import com.wsjt.service.SemmetryProperties;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.ObjectUtils;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * PBE是基于口令加密,加入了盐
 */
@Getter
@Setter
public class PbeSemmetryToJdk implements Semmetry {

    private SemmetryProperties sp;

    private final Logger logger = LoggerFactory.getLogger(PbeSemmetryToJdk.class);

    @Override
    public String encrypt(String src, Key key) {
        return encrypt(src, key, null);
    }

    @Override
    public String encrypt(byte[] src, Key key) {

        return encrypt(new String(src), key, null);
    }

    @Override
    public String encrypt(String src, Key key, byte[] salt) {
        //加密
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(ObjectUtils.isEmpty(salt) ? sp.getSecureRandom() : salt, 100);//用户没有定义盐就默认的
        try {
            Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES");
            cipher.init(Cipher.ENCRYPT_MODE, key, pbeParameterSpec);
            byte[] bytes = cipher.doFinal(src.getBytes());
            return sp.getBe().encode(bytes);    //返回的是用十六进制加密的

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
        } catch (InvalidAlgorithmParameterException e) {
            logger.trace("无效的算法参数", e);
        }

        return null;
    }


    @Override
    public String decrypt(String src, Key key) {
        return decrypt(src, key, null);
    }

    @Override
    public String decrypt(byte[] src, Key key) {
        return decrypt(sp.getBe().encode(src), key, null);
    }


    @Override
    public String decrypt(String src, Key key, byte[] salt) {

        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(ObjectUtils.isEmpty(salt) ? sp.getSecureRandom() : salt, 100);//用户没有定义盐就用默认的
        try {
            Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES");
            cipher.init(Cipher.DECRYPT_MODE, key, pbeParameterSpec);
            byte[] bytes = cipher.doFinal(sp.getDe().decodeBuffer(src));
            return new String(bytes);
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
        } catch (InvalidAlgorithmParameterException e) {
            logger.trace("无效的算法参数", e);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public Key generateKey() {
        try {
            //口令与加密

            PBEKeySpec pbeKeySpec = new PBEKeySpec(sp.getPassword().toCharArray());
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHMD5andDES");
            Key secretKey = factory.generateSecret(pbeKeySpec);
            return secretKey;
        } catch (NoSuchAlgorithmException e) {
            logger.trace("没有这样的算法", e);
        } catch (InvalidKeySpecException e) {
            logger.trace("无效的主要规范", e);
        }
        return null;
    }


}
