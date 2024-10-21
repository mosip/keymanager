package io.mosip.kernel.cryptomanager.test.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keymanager.hsm.impl.KeyStoreImpl;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.security.cert.Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;

import static org.junit.Assert.assertArrayEquals;
import static org.mockito.Mockito.*;
import static org.springframework.test.util.AssertionErrors.*;

@SpringBootTest(classes = KeymanagerTestBootApplication.class)
@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
public class CryptomanagerUtilsTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @MockBean
    CryptomanagerUtils cryptomanagerUtils;

    @MockBean
    KeymanagerUtil keymanagerUtil;

    @MockBean
    private KeymanagerService keyManager;

    @MockBean
    private KeymanagerDBHelper dbHelper;

    @MockBean
    KeyStoreImpl keyStore;

    private Certificate certificate;

    private CryptomanagerRequestDto requestDto;

    @Before
    public void setUp() {
        requestDto = new CryptomanagerRequestDto();
        requestDto.setData("Example");
        requestDto.setApplicationId("APPID");
        requestDto.setReferenceId("REFID");
        requestDto.setTimeStamp(LocalDateTime.now(ZoneId.of("UTC")));
        certificate = mock(Certificate.class);
    }

    @Test
    @WithUserDetails("reg-processor")
    public void getCertificateTest() {
        when(keymanagerUtil.convertToCertificate(anyString())).thenReturn(certificate);
    }

    @Test
    @WithUserDetails("reg-processor")
    public void nullOrTrimTest() {
        String result = CryptomanagerUtils.nullOrTrim(null);
        assertNull("Result should be null when input is null", result);

        result = CryptomanagerUtils.nullOrTrim("Any String");
        assertEquals("String trim and return","Any String", result);
    }

    @Test
    @WithUserDetails("reg-processor")
    public void inValidSaltTest() {
        boolean result = cryptomanagerUtils.isValidSalt("  ");
        assertFalse("Result should be False", result);
    }

    @Test
    @WithUserDetails("reg-processor")
    public void hexDecodeTest() {
        byte[] expected = "Hex-Decimal".getBytes();
        when(cryptomanagerUtils.hexDecode(anyString())).thenReturn(expected);
        byte[] actual = cryptomanagerUtils.hexDecode("Hex-Data");

        assertNotNull("The result should not be null", actual);
        assertArrayEquals("The result should match the expected value", expected, actual);
    }

    @Test
    @WithUserDetails("reg-processor")
    public void getCertificateThumbprintTest() {
        byte[] expectedThumbprint = "Certificate".getBytes();
        when(cryptomanagerUtils.getCertificateThumbprint(certificate)).thenReturn(expectedThumbprint);
        byte[] actualThumbprint = cryptomanagerUtils.getCertificateThumbprint(certificate);

        assertNotNull("The thumbprint should not be null", actualThumbprint);
        assertArrayEquals("The thumbprint should match the expected value", expectedThumbprint, actualThumbprint);
    }

    @Test
    @WithUserDetails("reg-processor")
    public void getCertificateThumbprintInHex() {
        String expected = "ThumbprintInHex";
        when(cryptomanagerUtils.getCertificateThumbprintInHex(certificate)).thenReturn(expected);
        String actual = cryptomanagerUtils.getCertificateThumbprintInHex(certificate);

        assertNotNull("The result should not be null", actual);
        assertEquals("The result should match the expected value", expected, actual);
    }

    @Test
    @WithUserDetails("reg-processor")
    public void concatCertThumbprintTest() {
        byte[] expected = "Final-Data".getBytes();
        when(cryptomanagerUtils.concatCertThumbprint(any(byte[].class), any(byte[].class))).thenReturn(expected);
        byte[] actual = cryptomanagerUtils.concatCertThumbprint(expected, expected);

        assertNotNull("The result should not be null", actual);
        assertEquals("The result should match the expected value", expected, actual);
    }
}
