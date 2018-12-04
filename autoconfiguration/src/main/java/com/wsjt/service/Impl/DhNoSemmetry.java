package com.wsjt.service.Impl;


import com.wsjt.service.NoSemmetry;
import com.wsjt.service.NoSemmetryProperties;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.interfaces.DHKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

@Getter
@Setter
public class DhNoSemmetry implements NoSemmetry {

    private final static Logger logger = LoggerFactory.getLogger(DhNoSemmetry.class);

    private NoSemmetryProperties sp;


    @Override
    public Map<String, ?> generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");//实例化密钥生成器
            keyPairGenerator.initialize(sp.getDhKeySize());//初始化密钥生成器
            KeyPair keyPair = keyPairGenerator.generateKeyPair();//生成密钥对
            DHPrivateKey aPrivate = (DHPrivateKey) keyPair.getPrivate();//获取甲方私钥
            DHPublicKey aPublic = (DHPublicKey) keyPair.getPublic();//获取甲方公钥
            Map<String, DHKey> map = new HashMap<>();//将他们封装在集合中,方便日后使用
            map.put(sp.getDhPublicKeyName(), aPublic);
            map.put(sp.getDhPrivateKeyName(), aPrivate);
            return map;

        } catch (NoSuchAlgorithmException e) {
            logger.trace("没有这样的算法名称", e);
        }
        return null;
    }

    @Override
    public Map<String, ?> generateKeyPair(byte[] Key) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Key);//将甲方公钥数组转为publicKey
        try {
            KeyFactory factory = KeyFactory.getInstance("DH"); //实例化工厂密钥对象
            DHPublicKey aPublicKey = (DHPublicKey) factory.generatePublic(x509EncodedKeySpec);//生成出甲方公钥
            DHParameterSpec params = aPublicKey.getParams();//剖解出甲方公钥,得到其参数
            KeyPairGenerator dh = KeyPairGenerator.getInstance("DH"); //初始化密钥生成器
            dh.initialize(params);//根据甲方参数,初始化密钥
            KeyPair keyPair = dh.generateKeyPair();//生成乙方的密钥对
            DHPublicKey bPublic = (DHPublicKey) keyPair.getPublic();//获取乙方公钥
            DHPrivateKey bPrivate = (DHPrivateKey) keyPair.getPrivate();//获取乙方私钥
            Map<String, DHKey> map = new HashMap<>();//将他们封装在集合中,方便日后使用
            map.put(sp.getDhPublicKeyName(), bPublic);
            map.put(sp.getDhPrivateKeyName(), bPrivate);
            return map;

        } catch (NoSuchAlgorithmException e) {
            logger.trace("没有这样的算法名称", e);
        } catch (InvalidKeySpecException e) {
            logger.trace("无效的键规范", e);
        } catch (InvalidAlgorithmParameterException e) {
            logger.trace("无效的算法参数", e);
        }

        return null;
    }

    @Override
    public SecretKey getSecretKey(byte[] publicKeyBtyes, byte[] privateKeyBytes) {
        try {
            KeyFactory factory = KeyFactory.getInstance("DH"); //先实例化密钥工厂
            X509EncodedKeySpec aPublicKey = new X509EncodedKeySpec(publicKeyBtyes);//根据甲方公钥数组转换为publicKey
            PublicKey aPublic = factory.generatePublic(aPublicKey);
            PKCS8EncodedKeySpec bPrivateKey = new PKCS8EncodedKeySpec(privateKeyBytes);//根据乙方公钥数组转换为privateKey
            final PrivateKey bPrivate = factory.generatePrivate(bPrivateKey);
            //根据甲方公钥和乙方私钥产生本地密钥对象
            KeyAgreement agreement = KeyAgreement.getInstance("DH");  //先实例化密钥名称
            agreement.init(bPrivate);  //根据自己的私钥初始化密钥
            agreement.doPhase(aPublic, true);//结合甲方的公钥进行运算
            SecretKey des = agreement.generateSecret("DES");
            return des;

        } catch (NoSuchAlgorithmException e) {
            logger.trace("没有这样的算法名称", e);
        } catch (InvalidKeySpecException e) {
            logger.trace("无效的键规范", e);
        } catch (InvalidKeyException e) {
            logger.trace("无效的键", e);
        }

        return null;
    }

    @Override
    public byte[] getSecretKeyBytes(byte[] publicKey, byte[] privateKey) {
        return getSecretKey(publicKey, privateKey).getEncoded();
    }

    @Override
    public String encrypt(String src, byte[] publicKey, byte[] privateKey) {
        SecretKey secretKey = getSecretKey(publicKey, privateKey);//创建密钥
        try {
            Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
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
        }
        return null;
    }

    @Override
    public String decrypt(String src, byte[] publicKey, byte[] privateKey) {
        SecretKey secretKey = getSecretKey(publicKey, privateKey);
        try {
            Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
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
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }
}
