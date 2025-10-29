
package io.mosip.kernel.cryptomanager.test.util;

import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Optional;

import io.mosip.kernel.core.exception.ParseException;
import io.mosip.kernel.cryptomanager.exception.CryptoManagerSerivceException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;

import io.mosip.kernel.core.keymanager.spi.ECKeyStore;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;

@SpringBootTest(classes = KeymanagerTestBootApplication.class)

@RunWith(SpringRunner.class)

@AutoConfigureMockMvc

@DirtiesContext(classMode = ClassMode.AFTER_EACH_TEST_METHOD)
public class CryptographicUtilExceptionTest {


	@Autowired
	CryptomanagerUtils cryptomanagerUtil;

	@MockBean
	private ECKeyStore keyStore;

	/** The key manager. */
	@MockBean
	private KeymanagerService keyManagerService;

	@Before
	public void setUp() {
		ReflectionTestUtils.setField(cryptomanagerUtil, "asymmetricAlgorithmName", "test");
	
	}

	@Test(expected = KeymanagerServiceException.class)
	public void testNoSuchAlgorithmEncrypt() throws Exception {
		KeyPairGenerateResponseDto keyPairGenerateResponseDto = new KeyPairGenerateResponseDto("badCertificateData", null, LocalDateTime.now(),
				LocalDateTime.now().plusDays(100), LocalDateTime.now());
		String appid = "REGISTRATION";
		String refid = "ref123";

		when(keyManagerService.getCertificate(Mockito.eq(appid), Mockito.eq(Optional.of(refid))))
				.thenReturn(keyPairGenerateResponseDto);
		CryptomanagerRequestDto cryptomanagerRequestDto = new CryptomanagerRequestDto("REGISTRATION", "ref123",
				LocalDateTime.parse("2018-12-06T12:07:44.403Z", DateTimeFormatter.ISO_DATE_TIME), "test",
				"ykrkpgjjtChlVdvDNJJEnQ", "VGhpcyBpcyBzYW1wbGUgYWFk", false);
		cryptomanagerUtil.getCertificate(cryptomanagerRequestDto);
	}

    @Test
    public void testNullOrTrim() {
        String result = CryptomanagerUtils.nullOrTrim(null);
        Assert.assertNull(result);

        result = CryptomanagerUtils.nullOrTrim("test");
        Assert.assertEquals("test", result);
    }

    @Test
    public void testValidSalt() {
        Assert.assertTrue(cryptomanagerUtil.isValidSalt("testSalt"));
        Assert.assertFalse(cryptomanagerUtil.isValidSalt(""));
        Assert.assertFalse(cryptomanagerUtil.isValidSalt(null));
    }

    @Test
    public void testParseLocalDateTime() {
        String timestamp = "2018-12-06T12:07:44.403Z";
        LocalDateTime localDateTime = cryptomanagerUtil.parseToLocalDateTime(timestamp);
        Assert.assertNotNull(localDateTime);
    }

    @Test
    public void testHexDecode() {
        String hexString = "63727970746F6D616E61676572207574696C20746573742063617365";
        byte[] result = cryptomanagerUtil.hexDecode(hexString);
        Assert.assertNotNull(result);
    }

    @Test(expected = ParseException.class)
    public void testHexDecodeException() {
        String hexString = "abc";
        cryptomanagerUtil.hexDecode(hexString);
    }

    @Test
    public void testConcatThumbprint() {
        byte[] thumbprint = "thumbprint".getBytes();
        byte[] key = "encryptedkey".getBytes();
        byte[] result = cryptomanagerUtil.concatCertThumbprint(thumbprint, key);
        Assert.assertEquals(44, result.length);

        cryptomanagerUtil.concatByteArrays(thumbprint, key);
        Assert.assertEquals(44, result.length);
    }

    @Test
    public void testGenerateRandomBytes() {
        byte[] result = cryptomanagerUtil.generateRandomBytes(10);
        Assert.assertNotNull(result);
    }

    @Test
    public void testDecodeBase64Data90() {
        byte[] result = cryptomanagerUtil.decodeBase64Data("dGVzdCBkYXRh");
        Assert.assertEquals("test data", new String(result));
    }

    @Test(expected = CryptoManagerSerivceException.class)
    public void testDecodeBase64DataException() {
        cryptomanagerUtil.decodeBase64Data("sh78ye32hu2^%");
    }

    @Test
    public void testHasAccess() {
        Assert.assertTrue(cryptomanagerUtil.hasKeyAccess("TEST"));
        Assert.assertFalse(cryptomanagerUtil.hasKeyAccess("INVALID_APP_ID"));
    }

    @Test(expected = CryptoManagerSerivceException.class)
    public void testValidateKeyIdentifierId() {
        cryptomanagerUtil.validateKeyIdentifierIds("TEST", null);
    }

    @Test(expected = CryptoManagerSerivceException.class)
    public void testCheckForValidJsonData() {
        cryptomanagerUtil.checkForValidJsonData("test");
    }

    @Test
    public void testIsJsonValid() {
        Assert.assertTrue(cryptomanagerUtil.isJsonValid("{\"test\": \"test\"}"));
        Assert.assertFalse(cryptomanagerUtil.isJsonValid("test"));
    }

    @Test
    public void testIsJWSData() {
        Assert.assertTrue(cryptomanagerUtil.isJWSData("header.payload.signature"));
        Assert.assertFalse(cryptomanagerUtil.isJWSData("payload.signature"));
    }
}
