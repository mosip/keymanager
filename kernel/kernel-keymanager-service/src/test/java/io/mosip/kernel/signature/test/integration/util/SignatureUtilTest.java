package io.mosip.kernel.signature.test.integration.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import io.mosip.kernel.signature.util.SignatureUtil;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class SignatureUtilTest {
    @Test
    public void testIsDataValid() {
        String validData = "Valid data";
        String emptyData = "";
        String nullData = null;

        Assert.assertTrue(SignatureUtil.isDataValid(validData));
        Assert.assertFalse(SignatureUtil.isDataValid(emptyData));
        Assert.assertFalse(SignatureUtil.isDataValid(nullData));
    }

    @Test
    public void testIsJsonValid() {
        String validJson = "{\"name\":\"John\",\"age\":30}";
        String invalidJson = "{\"name\":\"John\",\"age\":30";

        Assert.assertTrue(SignatureUtil.isJsonValid(validJson));
        Assert.assertFalse(SignatureUtil.isJsonValid(invalidJson));
    }

    @Test
    public void testIsIncludeAttrsValid() {
        Boolean includesTrue = true;
        Boolean includesFalse = false;
        Boolean includesNull = null;

        Assert.assertTrue(SignatureUtil.isIncludeAttrsValid(includesTrue));
        Assert.assertFalse(SignatureUtil.isIncludeAttrsValid(includesFalse));
    }

    @Test
    public void testIsCertificateDatesValid() throws CertificateEncodingException {
        X509Certificate validCertificate = Mockito.mock(X509Certificate.class);
        X509Certificate expiredCertificate = Mockito.mock(X509Certificate.class);
        X509Certificate notYetValidCertificate = Mockito.mock(X509Certificate.class);

        Mockito.when(validCertificate.getEncoded()).thenReturn(new byte[]{});
        Mockito.when(expiredCertificate.getEncoded()).thenThrow(CertificateEncodingException.class);
        Mockito.when(notYetValidCertificate.getEncoded()).thenThrow(CertificateEncodingException.class);

        Assert.assertTrue(SignatureUtil.isCertificateDatesValid(validCertificate));
    }

    @Test
    public void testBuildSignData() {
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
        byte[] actualDataToSign = "DataToSign".getBytes();

        byte[] signData = SignatureUtil.buildSignData(jwsHeader, actualDataToSign);
    }

}
