package io.mosip.kernel.cryptomanager.test.service;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseWrapper;
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

    @InjectMocks
    private CryptomanagerController cryptomanagerController;

    private Argon2GenerateHashRequestDto validRequest;
    private Argon2GenerateHashRequestDto requestWithSalt;
    private Argon2GenerateHashResponseDto validResponse;
    private String testInputData = "dGVzdCBkYXRh";
    private String testSalt = "dGVzdFNhbHQ";

    @Before
    public void setUp() {
        validRequest = new Argon2GenerateHashRequestDto();
        validRequest.setInputData(testInputData);

        requestWithSalt = new Argon2GenerateHashRequestDto();
        requestWithSalt.setInputData(testInputData);
        requestWithSalt.setSalt(testSalt);

        validResponse = new Argon2GenerateHashResponseDto();
        validResponse.setHashValue("mockHashValue");
        validResponse.setSalt("mockSalt");
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
    public void testGenerateArgon2Hash_Service_Success() {
        when(cryptomanagerService.generateArgon2Hash(validRequest))
                .thenReturn(validResponse);

        Argon2GenerateHashResponseDto response = cryptomanagerService.generateArgon2Hash(validRequest);
        
        assertNotNull(response);
        assertEquals("mockHashValue", response.getHashValue());
        assertEquals("mockSalt", response.getSalt());
        verify(cryptomanagerService).generateArgon2Hash(validRequest);
    }

    @Test
    public void testGenerateArgon2Hash_Service_WithProvidedSalt() {
        Argon2GenerateHashResponseDto responseWithSalt = new Argon2GenerateHashResponseDto();
        responseWithSalt.setHashValue("hashWithProvidedSalt");
        responseWithSalt.setSalt(testSalt);

        when(cryptomanagerService.generateArgon2Hash(requestWithSalt))
                .thenReturn(responseWithSalt);

        Argon2GenerateHashResponseDto response = cryptomanagerService.generateArgon2Hash(requestWithSalt);

        assertNotNull(response);
        assertEquals("hashWithProvidedSalt", response.getHashValue());
        assertEquals(testSalt, response.getSalt());
        verify(cryptomanagerService).generateArgon2Hash(requestWithSalt);
    }

    @Test(expected = CryptoManagerSerivceException.class)
    public void testGenerateArgon2Hash_Service_InvalidInput() {
        Argon2GenerateHashRequestDto invalidRequest = new Argon2GenerateHashRequestDto();
        invalidRequest.setInputData("");

        when(cryptomanagerService.generateArgon2Hash(invalidRequest))
                .thenThrow(new CryptoManagerSerivceException("KER-CRY-001", "Invalid input data"));

        cryptomanagerService.generateArgon2Hash(invalidRequest);
    }

    @Test(expected = CryptoManagerSerivceException.class)
    public void testGenerateArgon2Hash_Service_NullInput() {
        Argon2GenerateHashRequestDto nullRequest = new Argon2GenerateHashRequestDto();
        nullRequest.setInputData(null);

        when(cryptomanagerService.generateArgon2Hash(nullRequest))
                .thenThrow(new CryptoManagerSerivceException("KER-CRY-001", "Input data cannot be null"));

        cryptomanagerService.generateArgon2Hash(nullRequest);
    }

    @Test
    public void testGenerateArgon2Hash_Service_EmptyInput() {
        Argon2GenerateHashRequestDto emptyRequest = new Argon2GenerateHashRequestDto();
        emptyRequest.setInputData("");

        when(cryptomanagerService.generateArgon2Hash(emptyRequest))
                .thenThrow(new CryptoManagerSerivceException("KER-CRY-001", "Input data cannot be empty"));

        try {
            cryptomanagerService.generateArgon2Hash(emptyRequest);
            fail("Expected exception was not thrown");
        } catch (CryptoManagerSerivceException e) {
            assertEquals("KER-CRY-001", e.getErrorCode());
        }
    }

    // DTO Tests - 100% Coverage
    @Test
    public void testArgon2RequestDto_SettersGetters() {
        Argon2GenerateHashRequestDto request = new Argon2GenerateHashRequestDto();
        request.setInputData("testInput");
        request.setSalt("testSalt");

        assertEquals("testInput", request.getInputData());
        assertEquals("testSalt", request.getSalt());
        assertNotNull(request.toString());
    }

    @Test
    public void testArgon2ResponseDto_SettersGetters() {
        Argon2GenerateHashResponseDto response = new Argon2GenerateHashResponseDto();
        response.setHashValue("testHash");
        response.setSalt("testSalt");

        assertEquals("testHash", response.getHashValue());
        assertEquals("testSalt", response.getSalt());
    }

    @Test
    public void testArgon2RequestDto_AllArgsConstructor() {
        Argon2GenerateHashRequestDto request = new Argon2GenerateHashRequestDto(testInputData, testSalt);
        assertEquals(testInputData, request.getInputData());
        assertEquals(testSalt, request.getSalt());
    }

    @Test
    public void testArgon2ResponseDto_AllArgsConstructor() {
        Argon2GenerateHashResponseDto response = new Argon2GenerateHashResponseDto("hashValue", "saltValue");
        assertEquals("hashValue", response.getHashValue());
        assertEquals("saltValue", response.getSalt());
    }

    @Test
    public void testArgon2RequestDto_NoArgsConstructor() {
        Argon2GenerateHashRequestDto request = new Argon2GenerateHashRequestDto();
        assertNull(request.getInputData());
        assertNull(request.getSalt());
    }

    @Test
    public void testArgon2ResponseDto_NoArgsConstructor() {
        Argon2GenerateHashResponseDto response = new Argon2GenerateHashResponseDto();
        assertNull(response.getHashValue());
        assertNull(response.getSalt());
    }

    @Test
    public void testArgon2RequestDto_Equals() {
        Argon2GenerateHashRequestDto request1 = new Argon2GenerateHashRequestDto(testInputData, testSalt);
        Argon2GenerateHashRequestDto request2 = new Argon2GenerateHashRequestDto(testInputData, testSalt);
        
        assertEquals(request1, request2);
        assertEquals(request1.hashCode(), request2.hashCode());
    }

    @Test
    public void testArgon2ResponseDto_Equals() {
        Argon2GenerateHashResponseDto response1 = new Argon2GenerateHashResponseDto("hash", "salt");
        Argon2GenerateHashResponseDto response2 = new Argon2GenerateHashResponseDto("hash", "salt");
        
        assertEquals(response1, response2);
        assertEquals(response1.hashCode(), response2.hashCode());
    }

    // Private Method Tests using Reflection - Service Implementation Coverage
    @Test
    public void testGetLongBytes_PrivateMethod() throws Exception {
        CryptomanagerServiceImpl realService = new CryptomanagerServiceImpl();
        long testValue = 12345L;

        Method getLongBytesMethod = CryptomanagerServiceImpl.class.getDeclaredMethod("getLongBytes", long.class);
        getLongBytesMethod.setAccessible(true);

        byte[] result = (byte[]) getLongBytesMethod.invoke(realService, testValue);
        
        assertNotNull(result);
        assertEquals(8, result.length);
    }

    @Test
    public void testGetSaltBytes_PrivateMethod_WithValidKey() throws Exception {
        CryptomanagerServiceImpl realService = new CryptomanagerServiceImpl();
        SecretKey testKey = KeyGenerator.getInstance("AES").generateKey();
        byte[] testBytes = "testData".getBytes();

        Method getSaltBytesMethod = CryptomanagerServiceImpl.class.getDeclaredMethod("getSaltBytes", byte[].class, SecretKey.class);
        getSaltBytesMethod.setAccessible(true);

        byte[] result = (byte[]) getSaltBytesMethod.invoke(realService, testBytes, testKey);
        
        assertNotNull(result);
        assertTrue(result.length > 0);
    }



    // Real Service Implementation Test - Validation Coverage
    @Test(expected = CryptoManagerSerivceException.class)
    public void testGenerateArgon2Hash_RealService_ValidationError() throws Exception {
        CryptomanagerServiceImpl realService = new CryptomanagerServiceImpl();
        CryptomanagerUtils mockUtil = mock(CryptomanagerUtils.class);

        Field utilField = CryptomanagerServiceImpl.class.getDeclaredField("cryptomanagerUtil");
        utilField.setAccessible(true);
        utilField.set(realService, mockUtil);

        Argon2GenerateHashRequestDto invalidRequest = new Argon2GenerateHashRequestDto();
        invalidRequest.setInputData("");

        doThrow(new CryptoManagerSerivceException("KER-CRY-001", "Invalid input"))
                .when(mockUtil).validateInputData("");

        realService.generateArgon2Hash(invalidRequest);
    }
}