package io.mosip.kernel.cryptomanager.test.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.cache2k.Cache;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;

import de.mkammerer.argon2.Argon2Advanced;
import de.mkammerer.argon2.Argon2Factory;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.cryptomanager.constant.CryptomanagerConstant;
import io.mosip.kernel.cryptomanager.controller.CryptomanagerController;
import io.mosip.kernel.cryptomanager.dto.Argon2GenerateHashRequestDto;
import io.mosip.kernel.cryptomanager.dto.Argon2GenerateHashResponseDto;
import io.mosip.kernel.cryptomanager.exception.CryptoManagerSerivceException;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.kernel.cryptomanager.service.impl.CryptomanagerServiceImpl;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;

@RunWith(MockitoJUnitRunner.class)
public class Argon2HashServiceTest {

    @Mock
    private CryptomanagerService cryptomanagerService;

    @Mock
    private Cache<String, Object> saltGenParamsCache;

    @Mock
    private CryptomanagerUtils cryptomanagerUtil;

    @InjectMocks
    private CryptomanagerController cryptomanagerController;

    @InjectMocks
    private CryptomanagerServiceImpl cryptomanagerServiceImpl;

    private Argon2GenerateHashRequestDto validRequest;
    private Argon2GenerateHashRequestDto requestWithSalt;
    private Argon2GenerateHashResponseDto validResponse;
    private String testInputData = "dGVzdCBkYXRh";
    private String testSalt = "dGVzdFNhbHQ";

    @Before
    public void setUp() throws Exception {
        validRequest = new Argon2GenerateHashRequestDto();
        validRequest.setInputData(testInputData);

        requestWithSalt = new Argon2GenerateHashRequestDto();
        requestWithSalt.setInputData(testInputData);
        requestWithSalt.setSalt(testSalt);

        validResponse = new Argon2GenerateHashResponseDto();
        validResponse.setHashValue("mockHashValue");
        validResponse.setSalt("mockSalt");

        // Initialize private fields in CryptomanagerServiceImpl for Argon2
        Field iterationsField = CryptomanagerServiceImpl.class.getDeclaredField("argon2Iterations");
        iterationsField.setAccessible(true);
        iterationsField.set(cryptomanagerServiceImpl, 2);

        Field memoryField = CryptomanagerServiceImpl.class.getDeclaredField("argon2Memory");
        memoryField.setAccessible(true);
        memoryField.set(cryptomanagerServiceImpl, 1024);

        Field parallelismField = CryptomanagerServiceImpl.class.getDeclaredField("argon2Parallelism");
        parallelismField.setAccessible(true);
        parallelismField.set(cryptomanagerServiceImpl, 1);
    }

    @Test
    public void testGenerateArgon2Hash_Controller_Success() {
        RequestWrapper<Argon2GenerateHashRequestDto> requestWrapper = new RequestWrapper<>();
        requestWrapper.setRequest(validRequest);

        when(cryptomanagerService.generateArgon2Hash(any(Argon2GenerateHashRequestDto.class)))
                .thenReturn(validResponse);

        ResponseWrapper<Argon2GenerateHashResponseDto> response = 
                cryptomanagerController.generateArgon2Hash(requestWrapper);

        assertNotNull(response);
        assertNotNull(response.getResponse());
        assertEquals("mockHashValue", response.getResponse().getHashValue());
        assertEquals("mockSalt", response.getResponse().getSalt());
        verify(cryptomanagerService).generateArgon2Hash(validRequest);
    }

    @Test
    public void testGenerateArgon2Hash_Controller_WithSalt() {
        RequestWrapper<Argon2GenerateHashRequestDto> requestWrapper = new RequestWrapper<>();
        requestWrapper.setRequest(requestWithSalt);

        Argon2GenerateHashResponseDto responseWithSalt = new Argon2GenerateHashResponseDto();
        responseWithSalt.setHashValue("hashWithSalt");
        responseWithSalt.setSalt(testSalt);

        when(cryptomanagerService.generateArgon2Hash(any(Argon2GenerateHashRequestDto.class)))
                .thenReturn(responseWithSalt);

        ResponseWrapper<Argon2GenerateHashResponseDto> response = 
                cryptomanagerController.generateArgon2Hash(requestWrapper);

        assertNotNull(response);
        assertEquals("hashWithSalt", response.getResponse().getHashValue());
        assertEquals(testSalt, response.getResponse().getSalt());
        verify(cryptomanagerService).generateArgon2Hash(requestWithSalt);
    }

    @Test(expected = CryptoManagerSerivceException.class)
    public void testGenerateArgon2Hash_Controller_ServiceException() {
        RequestWrapper<Argon2GenerateHashRequestDto> requestWrapper = new RequestWrapper<>();
        requestWrapper.setRequest(validRequest);

        when(cryptomanagerService.generateArgon2Hash(any(Argon2GenerateHashRequestDto.class)))
                .thenThrow(new CryptoManagerSerivceException("KER-CRY-001", "Invalid request"));

        cryptomanagerController.generateArgon2Hash(requestWrapper);
    }

    @Test
    public void testGenerateArgon2Hash_Controller_NullRequest() {
        RequestWrapper<Argon2GenerateHashRequestDto> requestWrapper = new RequestWrapper<>();
        requestWrapper.setRequest(null);

        when(cryptomanagerService.generateArgon2Hash(null))
                .thenThrow(new CryptoManagerSerivceException("KER-CRY-001", "Request cannot be null"));

        try {
            cryptomanagerController.generateArgon2Hash(requestWrapper);
            fail("Expected exception was not thrown");
        } catch (CryptoManagerSerivceException e) {
            assertEquals("KER-CRY-001", e.getErrorCode());
        }
    }

    @Test
    public void testGenerateArgon2HashWithGeneratedSalt() {
        Argon2GenerateHashRequestDto request = new Argon2GenerateHashRequestDto();
        request.setInputData("testPassword");
        request.setSalt(null);

        SecretKey mockAesKey = new SecretKeySpec(new byte[16], "AES");
        AtomicLong mockCounter = new AtomicLong(12345L);

        byte[] dummyHash = "dummyHash".getBytes();
        Argon2Advanced argon2AdvancedMock = mock(Argon2Advanced.class);
        when(argon2AdvancedMock.rawHash(anyInt(), anyInt(), anyInt(), any(char[].class), any(byte[].class)))
                .thenReturn(dummyHash);

        try (MockedStatic<Argon2Factory> argon2Factory = mockStatic(Argon2Factory.class)) {
            argon2Factory.when(() -> Argon2Factory.createAdvanced(any())).thenReturn(argon2AdvancedMock);

            when(saltGenParamsCache.get(CryptomanagerConstant.CACHE_AES_KEY)).thenReturn(mockAesKey);
            when(saltGenParamsCache.get(CryptomanagerConstant.CACHE_INT_COUNTER)).thenReturn(mockCounter);
            doNothing().when(cryptomanagerUtil).validateInputData(anyString());
            when(cryptomanagerUtil.isDataValid(any())).thenReturn(false);

            Argon2GenerateHashResponseDto response = cryptomanagerServiceImpl.generateArgon2Hash(request);

            assertNotNull(response.getHashValue());
            assertNotNull(response.getSalt());
            assertEquals(CryptoUtil.encodeToURLSafeBase64(dummyHash), response.getHashValue());
            verify(cryptomanagerUtil).validateInputData("testPassword");
            verify(saltGenParamsCache).put(eq(CryptomanagerConstant.CACHE_INT_COUNTER), any(AtomicLong.class));
        }
    }

    @Test
    public void testGenerateArgon2HashWithProvidedSalt() {
        String providedSalt = CryptoUtil.encodeToURLSafeBase64("testSalt".getBytes());
        Argon2GenerateHashRequestDto request = new Argon2GenerateHashRequestDto();
        request.setInputData("testPassword");
        request.setSalt(providedSalt);

        byte[] dummyHash = "dummyHash".getBytes();
        Argon2Advanced argon2AdvancedMock = mock(Argon2Advanced.class);
        when(argon2AdvancedMock.rawHash(anyInt(), anyInt(), anyInt(), any(char[].class), any(byte[].class)))
                .thenReturn(dummyHash);

        try (MockedStatic<Argon2Factory> argon2Factory = mockStatic(Argon2Factory.class)) {
            argon2Factory.when(() -> Argon2Factory.createAdvanced(any())).thenReturn(argon2AdvancedMock);

            doNothing().when(cryptomanagerUtil).validateInputData(anyString());
            when(cryptomanagerUtil.isDataValid(providedSalt)).thenReturn(true);

            Argon2GenerateHashResponseDto response = cryptomanagerServiceImpl.generateArgon2Hash(request);

            assertNotNull(response.getHashValue());
            assertEquals(providedSalt, response.getSalt());
            assertEquals(CryptoUtil.encodeToURLSafeBase64(dummyHash), response.getHashValue());
            verify(cryptomanagerUtil).validateInputData("testPassword");
        }
    }

    @Test
    public void testGenerateArgon2HashWithSaltGenerationFallback() {
        Argon2GenerateHashRequestDto request = new Argon2GenerateHashRequestDto();
        request.setInputData("testPassword");
        request.setSalt(null);

        byte[] dummyHash = "dummyHash".getBytes();
        Argon2Advanced argon2AdvancedMock = mock(Argon2Advanced.class);
        when(argon2AdvancedMock.rawHash(anyInt(), anyInt(), anyInt(), any(char[].class), any(byte[].class)))
                .thenReturn(dummyHash);

        try (MockedStatic<Argon2Factory> argon2Factory = mockStatic(Argon2Factory.class)) {
            argon2Factory.when(() -> Argon2Factory.createAdvanced(any())).thenReturn(argon2AdvancedMock);

            when(saltGenParamsCache.get(CryptomanagerConstant.CACHE_AES_KEY)).thenReturn(null);
            doNothing().when(cryptomanagerUtil).validateInputData(anyString());
            when(cryptomanagerUtil.isDataValid(any())).thenReturn(false);

            Argon2GenerateHashResponseDto response = cryptomanagerServiceImpl.generateArgon2Hash(request);

            assertNotNull(response.getHashValue());
            assertNotNull(response.getSalt());
            assertEquals(CryptoUtil.encodeToURLSafeBase64(dummyHash), response.getHashValue());
            verify(cryptomanagerUtil).validateInputData("testPassword");
        }
    }
}
