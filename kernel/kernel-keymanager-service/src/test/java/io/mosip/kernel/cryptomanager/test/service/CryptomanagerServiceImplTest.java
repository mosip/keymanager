package io.mosip.kernel.cryptomanager.test.service;

import io.mosip.kernel.cryptomanager.dto.*;
import io.mosip.kernel.cryptomanager.service.impl.CryptomanagerServiceImpl;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keymanagerservice.helper.PrivateKeyDecryptorHelper;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@SpringBootTest(classes = KeymanagerTestBootApplication.class)
@RunWith(SpringRunner.class)
public class CryptomanagerServiceImplTest {

    @Autowired
    CryptomanagerServiceImpl service;

    @MockBean
    CryptomanagerUtils cryptomanagerUtils;

    private String appId = "PRE_REGISTRATION";

    private String refId = "refer";

    private String data = "e25hbWU6ICJKdW5pdCIsIHB1cnBvc2U6ICJUZXN0aW5nIn0=";

    private String certStr;

    private Certificate cert;

    String privateKey;

    @Before
    public void init() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 1064L * 24 * 60 * 60 * 1000);
        X500Name dnName = new X500Name("C=IN, ST=Karnataka, O=CyberPWN, OU=Product Team, CN=Testing");
        BigInteger serial = BigInteger.valueOf(now);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, serial, startDate, endDate, dnName, keyPair.getPublic());
        cert = (Certificate) new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(signer));

        certStr = convertToPEM(cert);
    }

    public static String convertToPEM(Certificate cert) throws Exception {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(cert);
        }
        return stringWriter.toString();
    }

    @Test
    @WithUserDetails("reg-processor")
    public void testJwtEncrypt() {
        JWTEncryptRequestDto requestDto = new JWTEncryptRequestDto();
        requestDto.setApplicationId(appId);
        requestDto.setReferenceId(refId);
        requestDto.setData(data);

        when(cryptomanagerUtils.getCertificate(requestDto.getApplicationId(), requestDto.getReferenceId())).thenReturn(cert);
        JWTCipherResponseDto responseDto = service.jwtEncrypt(requestDto);

        Assert.assertNotNull(responseDto);
    }

    @Test
    @WithUserDetails("reg-processor")
    public void testException () throws JoseException {
        JWTEncryptRequestDto requestDto = new JWTEncryptRequestDto();
        requestDto.setApplicationId(appId);
        requestDto.setReferenceId(refId);
        requestDto.setData(data);

        Exception exception = assertThrows(
                Exception.class,
                () -> service.jwtEncrypt(requestDto)
        );

        assertNotNull(exception);

        JsonWebEncryption jsonWebEncrypt = new JsonWebEncryption();
        exception = assertThrows(
                Exception.class,
                () -> jsonWebEncrypt.getCompactSerialization()
        );

        assertNotNull(exception);
    }
}
