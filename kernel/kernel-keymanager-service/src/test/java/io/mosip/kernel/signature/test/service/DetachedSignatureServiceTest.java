package io.mosip.kernel.signature.test.service;

import io.mosip.kernel.core.keymanager.model.CertificateEntry;
import io.mosip.kernel.crypto.jce.core.CryptoCore;
import io.mosip.kernel.keymanagerservice.dto.SignatureCertificate;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.signature.dto.SignRequestDto;
import io.mosip.kernel.signature.service.impl.SignatureServiceImpl;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jca.ProviderContext;
import org.jose4j.jws.JsonWebSignature;
import org.junit.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DetachedSignatureServiceTest {

    @Test
    public void signsP256AsEs256() throws Exception {
        assertDetachedSignature("secp256r1", "ES256");
    }

    @Test
    public void signsSecp256k1AsEs256k() throws Exception {
        assertDetachedSignature("secp256k1", "ES256K");
    }

    private void assertDetachedSignature(String curve, String expectedAlgorithm) throws Exception {
        var keymanager = mock(KeymanagerService.class);
        var service = new SignatureServiceImpl();
        ReflectionTestUtils.setField(service, "keymanagerService", keymanager);
        ReflectionTestUtils.setField(service, "keymanagerUtil", mock(KeymanagerUtil.class));
        ReflectionTestUtils.setField(service, "cryptoCore", new CryptoCore());
        ReflectionTestUtils.setField(service, "signApplicationid", "KERNEL");
        ReflectionTestUtils.setField(service, "signRefid", "SIGN");
        ReflectionTestUtils.setField(service, "enableSecp256k1Algo", true);
        service.init();

        String provider = BouncyCastleProvider.PROVIDER_NAME;
        var generator = KeyPairGenerator.getInstance("EC", provider);
        generator.initialize(new ECGenParameterSpec(curve));
        var keyPair = generator.generateKeyPair();
        var certificate = mock(X509Certificate.class);
        when(certificate.getPublicKey()).thenReturn(keyPair.getPublic());

        var entry = new CertificateEntry<>(new X509Certificate[]{certificate}, keyPair.getPrivate());
        var signingCertificate = new SignatureCertificate(null, entry, null, null, provider, null);
        when(keymanager.getSignatureCertificate(eq("KERNEL"), eq(Optional.of("SIGN")), anyString()))
                .thenReturn(signingCertificate);

        var request = new SignRequestDto();
        request.setData("test");
        String compactJws = service.sign(request).getData();

        assertEquals("", compactJws.split("\\.", -1)[1]);
        var jws = new JsonWebSignature();
        jws.setCompactSerialization(compactJws);
        assertEquals(expectedAlgorithm, jws.getAlgorithmHeaderValue());
        assertEquals(null, jws.getHeader("x5c"));

        var providerContext = new ProviderContext();
        providerContext.getSuppliedKeyProviderContext().setSignatureProvider(provider);
        jws.setProviderContext(providerContext);
        jws.setPayload(request.getData());
        jws.setKey(keyPair.getPublic());
        assertTrue(jws.verifySignature());
    }
}
