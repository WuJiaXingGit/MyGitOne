package com.wsjt.service;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.security.SecureRandom;

@Data
@ConfigurationProperties(prefix = "wsjt-semmetry")
public class SemmetryProperties {

    private int aesKeySize = 128;

    private int des3KeySize = 168;

    private int desKeySize = 56;

    private String password = "wujiaxing"; //口令

    private byte[] secureRandom = secureRandom(8);//默认的盐;

    private BASE64Encoder be = new BASE64Encoder();

    private BASE64Decoder de = new BASE64Decoder();

    /**
     * @param numByets 是盐的长度
     * @return
     */

    public byte[] secureRandom(int numByets) {
        //初始化盐
        SecureRandom random = new SecureRandom();//其实就是一组随机数
        byte[] bytes = random.generateSeed(numByets);
        return bytes;
    }
}
