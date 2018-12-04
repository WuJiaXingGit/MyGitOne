package com.wsjt.service.Impl;

import com.wsjt.service.NoSemmetry;
import com.wsjt.service.NoSemmetryProperties;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

@Getter
@Setter
public class RsaNoSemmetry implements NoSemmetry {

    private final static Logger logger = LoggerFactory.getLogger(RsaNoSemmetry.class);

    private NoSemmetryProperties sp;

    @Override
    public Map<String, ?> generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(sp.getRsaKeySize());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey keyPairPublic = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey keyPairPrivate = (RSAPrivateKey) keyPair.getPrivate();
            Map<String, RSAKey> map = new HashMap<>();
            map.put(sp.getRsaPublicKeyName(), keyPairPublic);
            map.put(sp.getRsaPrivateKeyName(), keyPairPrivate);
            return map;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }


    @Override
    public String pulbicKeyEncrypt(String src, byte[] publicKey) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey aPublic = factory.generatePublic(x509EncodedKeySpec);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, aPublic);
            byte[] bytes = cipher.doFinal(src.getBytes());
            return sp.getBe().encode(bytes);

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
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public String privateKeyEncrypt(String src, byte[] privateKey) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey1 = factory.generatePrivate(pkcs8EncodedKeySpec);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey1);
            byte[] bytes = cipher.doFinal(src.getBytes());
            return sp.getBe().encode(bytes);

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
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public String pulbicKeyDecrypt(String src, byte[] publicKey) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey aPublic = factory.generatePublic(x509EncodedKeySpec);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, aPublic);
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
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public String privateKeyDecrypt(String src, byte[] privateKey) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey1 = factory.generatePrivate(pkcs8EncodedKeySpec);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey1);
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
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }
}
