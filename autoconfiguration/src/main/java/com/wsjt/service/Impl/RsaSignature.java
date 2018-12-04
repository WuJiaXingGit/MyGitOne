package com.wsjt.service.Impl;


import com.wsjt.service.SignatureToJdk;
import com.wsjt.service.SignatureProperties;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
public class RsaSignature implements SignatureToJdk {

    private final static Logger logger = LoggerFactory.getLogger(RsaSignature.class);
    private SignatureProperties sp;

    @Override
    public Map<String, ?> generateKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(sp.getRsaKeySize());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey aPublic = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey aPrivate = (RSAPrivateKey) keyPair.getPrivate();
            Map<String, RSAKey> map = new HashMap<>();
            map.put(sp.getRsaPublicKey(), aPublic);
            map.put(sp.getRsaPrivateKey(), aPrivate);
            return map;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public String getSignature(String src, byte[] privateKey) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey1 = factory.generatePrivate(pkcs8EncodedKeySpec);
            Signature rsa = Signature.getInstance("MD5withRSA");
            rsa.initSign(privateKey1);
            rsa.update(src.getBytes());
            byte[] sign = rsa.sign();
            return sp.getBe().encode(sign);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public boolean verifySignature(String src, String result, byte[] publicKey) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey aPublic = factory.generatePublic(x509EncodedKeySpec);
            Signature rsa = Signature.getInstance("MD5withRSA");
            rsa.initVerify(aPublic);
            rsa.update(src.getBytes());
            boolean verify = rsa.verify(sp.getDe().decodeBuffer(result));
            return verify;

        } catch (NoSuchAlgorithmException e) {
            logger.trace("没有这样的算法", e.getStackTrace());
        } catch (InvalidKeyException e) {
            logger.trace("无效的key", e);
        } catch (SignatureException e) {
            logger.trace("签名异常", e.getStackTrace());
        } catch (InvalidKeySpecException e) {
            logger.trace("无效的key规范", e.getStackTrace());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }
}
