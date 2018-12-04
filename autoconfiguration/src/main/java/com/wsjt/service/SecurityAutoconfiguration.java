package com.wsjt.service;

import com.wsjt.service.Impl.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties({SemmetryProperties.class, NoSemmetryProperties.class, SignatureProperties.class})
public class SecurityAutoconfiguration {

    @Autowired
    private SemmetryProperties sp;

    @Autowired
    private NoSemmetryProperties nsp;

    @Autowired
    private SignatureProperties stp;



    @Configuration
    class Semmetry{

        @Bean
        public AesSemmetryToJdk aesSemmetry() {
            AesSemmetryToJdk aesSemmetryToJdk = new AesSemmetryToJdk();
            aesSemmetryToJdk.setSp(sp);
            return aesSemmetryToJdk;
        }

        @Bean
        @ConditionalOnMissingBean(name = "des3SemmetryToJdk")
        public Des3SemmetryToJdk des3Semmetry() {
            Des3SemmetryToJdk des3SemmetryToJdk = new Des3SemmetryToJdk();
            des3SemmetryToJdk.setSp(sp);
            return des3SemmetryToJdk;
        }

        @Bean
        public DesSemmetryToJdk desSemmetry() {
            DesSemmetryToJdk desSemmetryToJdk = new DesSemmetryToJdk();
            desSemmetryToJdk.setSp(sp);
            return desSemmetryToJdk;
        }

        @Bean
        public PbeSemmetryToJdk pbeSemmetry() {
            PbeSemmetryToJdk pbeSemmetryToJdk = new PbeSemmetryToJdk();
            pbeSemmetryToJdk.setSp(sp);
            return pbeSemmetryToJdk;
        }
    }





        @Configuration
        class NoSemmetry{
            @Bean
            public DhNoSemmetry dhNoSemmetry() {
                DhNoSemmetry dhNoSemmetry = new DhNoSemmetry();
                dhNoSemmetry.setSp(nsp);
                return dhNoSemmetry;
            }

            @Bean
            public RsaNoSemmetry rsaNoSemmetry() {
                RsaNoSemmetry rsaNoSemmetry = new RsaNoSemmetry();
                rsaNoSemmetry.setSp(nsp);
                return rsaNoSemmetry;
            }

            @Bean
            public KeyUtils keyUtils() {
                KeyUtils keyUtils = new KeyUtils();
                KeyUtils.setSp(nsp);
                return keyUtils;
            }

        }


        @Configuration
         class Signature{

            @Bean
            public RsaSignature rsaSignature() {
                RsaSignature rsaSignature = new RsaSignature();
                rsaSignature.setSp(stp);
                return rsaSignature;
            }
        }

    }



