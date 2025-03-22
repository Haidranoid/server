package io._2connect.server.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class RSAService {
    public static final String RSA = "RSA";

    private final JwtProperties properties;

    @Bean
    KeyFactory keyFactory() throws NoSuchAlgorithmException {

        return KeyFactory.getInstance(RSA);
    }

    @Bean
    RSAPrivateKey jwtPrivateKey(KeyFactory keyFactory) throws InvalidKeySpecException {

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(properties.getPrivateKey()));

        return (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
    }

    @Bean
    RSAPublicKey jwtPublicKey(KeyFactory keyFactory) throws InvalidKeySpecException {

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(properties.getPublicKey()));

        return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
    }
}
