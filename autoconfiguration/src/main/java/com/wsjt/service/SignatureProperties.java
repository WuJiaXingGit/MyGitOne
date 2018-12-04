package com.wsjt.service;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

@Data
@ConfigurationProperties(prefix = "wsjt-signature")
public class SignatureProperties {

    private String rsaPublicKey = "publicKey";

    private String rsaPrivateKey = "privateKey";

    private int rsaKeySize = 512;

    private BASE64Encoder be = new BASE64Encoder();

    private BASE64Decoder de = new BASE64Decoder();
}
