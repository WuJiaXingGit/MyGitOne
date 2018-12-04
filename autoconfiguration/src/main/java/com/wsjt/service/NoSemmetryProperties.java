package com.wsjt.service;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

@Data
@ConfigurationProperties(prefix = "wsjt-nosemmetry")
public class NoSemmetryProperties {

    private String dhPublicKeyName = "dhPublicKey";

    private String dhPrivateKeyName = "dhPrivateKey";

    private String rsaPublicKeyName = "rsaPublicKey";

    private String rsaPrivateKeyName = "rsaPrivateKey";

    private int dhKeySize = 1024;

    private int rsaKeySize = 1024;

    private BASE64Encoder be = new BASE64Encoder();

    private BASE64Decoder de = new BASE64Decoder();


}
