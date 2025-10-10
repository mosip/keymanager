package io.mosip.kernel.signature.test.service;

import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.signature.dto.*;
import io.mosip.kernel.signature.exception.RequestException;
import io.mosip.kernel.signature.exception.SignatureFailureException;
import io.mosip.kernel.signature.service.CoseSignatureService;
import io.mosip.kernel.signature.service.impl.CoseSignatureServiceImpl;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOError;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
public class CoseSignatureServiceTest {

    @Autowired
    private CoseSignatureService coseSignatureService;

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private KeyAliasRepository keyAliasRepository;

    @Before
    public void setUp() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ROOT");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
    }

    @After
    public void tearDown() {
        keyAliasRepository.deleteAll();
    }

    @Test
    public void testCoseSign1() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        CoseSignRequestDto coseSignRequestDto = new CoseSignRequestDto();
        coseSignRequestDto.setApplicationId("TEST");
        coseSignRequestDto.setReferenceId("");
        coseSignRequestDto.setPayload(CryptoUtil.encodeToURLSafeBase64("test payload".getBytes()));
        coseSignRequestDto.setAlgorithm("RS256");
        
        CoseSignResponseDto response = coseSignatureService.coseSign1(coseSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getSignedData());

    }

    @Test
    public void testCoseSign1WithECKey() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("EC_SECP256R1_SIGN");
        keymanagerService.generateECSignKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        CoseSignRequestDto coseSignRequestDto = new CoseSignRequestDto();
        coseSignRequestDto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        CoseSignResponseDto response = coseSignatureService.coseSign1(coseSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getSignedData());

        coseSignRequestDto.setApplicationId("TEST");
        coseSignRequestDto.setReferenceId("EC_SECP256R1_SIGN");
        response = coseSignatureService.coseSign1(coseSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getSignedData());
    }

    @Test
    public void testCoseSign1WithEd25519Key() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setReferenceId("ED25519_SIGN");
        keymanagerService.generateECSignKey("CSR", keyPairGenRequestDto);

        CoseSignRequestDto coseSignRequestDto = new CoseSignRequestDto();
        coseSignRequestDto.setApplicationId("TEST");
        coseSignRequestDto.setReferenceId("ED25519_SIGN");
        coseSignRequestDto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        CoseSignResponseDto response = coseSignatureService.coseSign1(coseSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getSignedData());
    }

    @Test
    public void testCoseSignWithHeader() {
        Map<String, Object> protectedHeader = new HashMap<>();
        protectedHeader.put("crit", "kid, alg");
        protectedHeader.put("cty", "application/cbor");
        protectedHeader.put("includeCertificateChain", true);
        protectedHeader.put("includeCertificateHash", true);
        protectedHeader.put("certificateUrl", "https://test.com/cert");
        protectedHeader.put("kid", true);
        protectedHeader.put("iv", "njsancsalkjcaisjka");
        protectedHeader.put("additional Testheader", "test additional header parameter");

        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        CoseSignRequestDto coseSignRequestDto = new CoseSignRequestDto();
        coseSignRequestDto.setApplicationId("TEST");
        coseSignRequestDto.setReferenceId("");
        coseSignRequestDto.setProtectedHeader(protectedHeader);
        coseSignRequestDto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        CoseSignResponseDto response = coseSignatureService.coseSign1(coseSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getSignedData());

        Map<String, Object> unprotectedHeader = new HashMap<>();
        unprotectedHeader.put("additional Testheader", "test additional header parameter");
        unprotectedHeader.put("additional Testheader2", "test additional header parameter2");
        unprotectedHeader.put("cty", "application/cbor");
        unprotectedHeader.put("includeCertificate", true);
        unprotectedHeader.put("includeCertificateHash", true);
        unprotectedHeader.put("certificateUrl", "https://test.com/cert");
        unprotectedHeader.put("kid", true);
        unprotectedHeader.put("partial-iv", "njsancsalkjcaisjka");

        coseSignRequestDto.setProtectedHeader(null);
        coseSignRequestDto.setUnprotectedHeader(unprotectedHeader);
        response = coseSignatureService.coseSign1(coseSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getSignedData());
    }

    @Test(expected = RequestException.class)
    public void testCoseSignRequestException() {
        CoseSignRequestDto coseSignRequestDto = new CoseSignRequestDto();
        coseSignRequestDto.setApplicationId("INVALID_APP_ID");
        coseSignRequestDto.setPayload("ghjh");
        coseSignatureService.coseSign1(coseSignRequestDto);

        coseSignRequestDto.setPayload("");
        coseSignatureService.coseSign1(coseSignRequestDto);
    }

    @Test
    public void testCoseSign1EmptyPayload() {
        CoseSignRequestDto coseSignRequestDto = new CoseSignRequestDto();
        coseSignRequestDto.setPayload("");
        
        RequestException exception = assertThrows(RequestException.class, () -> {
            coseSignatureService.coseSign1(coseSignRequestDto);
        });
        Assert.assertNotNull(exception);
    }

    @Test
    public void testCoseVerify1() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        CoseSignRequestDto coseSignRequestDto = new CoseSignRequestDto();
        coseSignRequestDto.setApplicationId("TEST");
        coseSignRequestDto.setReferenceId("");
        coseSignRequestDto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        CoseSignResponseDto signResponse = coseSignatureService.coseSign1(coseSignRequestDto);
        
        // Then verify it
        CoseSignVerifyRequestDto coseSignVerifyRequestDto = new CoseSignVerifyRequestDto();
        coseSignVerifyRequestDto.setApplicationId("TEST");
        coseSignVerifyRequestDto.setReferenceId("");
        coseSignVerifyRequestDto.setCoseSignedData(signResponse.getSignedData());
        CoseSignVerifyResponseDto verifyResponse = coseSignatureService.coseVerify1(coseSignVerifyRequestDto);
        
        Assert.assertNotNull(verifyResponse);
        Assert.assertTrue(verifyResponse.isSignatureValid());
        Assert.assertEquals("Validation Successful", verifyResponse.getMessage());
    }

    @Test
    public void testCoseVerify1WithTrustValidation() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("EC_SECP256K1_SIGN");
        keymanagerService.generateECSignKey("CSR", keyPairGenRequestDto);

        CoseSignRequestDto coseSignRequestDto = new CoseSignRequestDto();
        coseSignRequestDto.setApplicationId("TEST");
        coseSignRequestDto.setReferenceId("EC_SECP256K1_SIGN");
        coseSignRequestDto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        CoseSignResponseDto signResponse = coseSignatureService.coseSign1(coseSignRequestDto);

        CoseSignVerifyRequestDto coseSignVerifyRequestDto = new CoseSignVerifyRequestDto();
        coseSignVerifyRequestDto.setApplicationId("TEST");
        coseSignVerifyRequestDto.setReferenceId("EC_SECP256K1_SIGN");
        coseSignVerifyRequestDto.setCoseSignedData(signResponse.getSignedData());
        coseSignVerifyRequestDto.setValidateTrust(true);
        coseSignVerifyRequestDto.setDomain("DEVICE");
        
        CoseSignVerifyResponseDto verifyResponse = coseSignatureService.coseVerify1(coseSignVerifyRequestDto);
        Assert.assertNotNull(verifyResponse);
    }

    @Test
    public void testCoseVerify1InvalidData() {
        CoseSignVerifyRequestDto coseSignVerifyRequestDto = new CoseSignVerifyRequestDto();
        coseSignVerifyRequestDto.setCoseSignedData("invalid-hex-data");
        
        SignatureFailureException exception = assertThrows(SignatureFailureException.class, () -> {
            coseSignatureService.coseVerify1(coseSignVerifyRequestDto);
        });
        Assert.assertNotNull(exception);
    }

    @Test
    public void testCoseVerify1EmptyData() {
        CoseSignVerifyRequestDto coseSignVerifyRequestDto = new CoseSignVerifyRequestDto();
        coseSignVerifyRequestDto.setCoseSignedData("");
        
        RequestException exception = assertThrows(RequestException.class, () -> {
            coseSignatureService.coseVerify1(coseSignVerifyRequestDto);
        });
        Assert.assertNotNull(exception);
    }

    @Test(expected = RequestException.class)
    public void testCoseVerifyTag() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ID_REPO");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        CWTSignRequestDto cwtSignRequestDto = new CWTSignRequestDto();
        cwtSignRequestDto.setApplicationId("ID_REPO");
        cwtSignRequestDto.setReferenceId("");
        cwtSignRequestDto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        CoseSignResponseDto response = coseSignatureService.cwtSign(cwtSignRequestDto);

        CoseSignVerifyRequestDto coseSignVerifyRequestDto = new CoseSignVerifyRequestDto();
        coseSignVerifyRequestDto.setApplicationId("ID_REPO");
        coseSignVerifyRequestDto.setReferenceId("");
        coseSignVerifyRequestDto.setCoseSignedData(response.getSignedData());
        coseSignatureService.coseVerify1(coseSignVerifyRequestDto);
    }

    @Test
    public void testCwtSign() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ID_REPO");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        CWTSignRequestDto cwtSignRequestDto = new CWTSignRequestDto();
        cwtSignRequestDto.setApplicationId("ID_REPO");
        cwtSignRequestDto.setReferenceId("");
        cwtSignRequestDto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        CoseSignResponseDto response = coseSignatureService.cwtSign(cwtSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getSignedData());
        Assert.assertNotNull(response.getTimestamp());
    }

    @Test
    public void testCwtSignWithClaim169() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ID_REPO");
        keyPairGenRequestDto.setReferenceId("EC_SECP256R1_SIGN");
        keymanagerService.generateECSignKey("CSR", keyPairGenRequestDto);

        CWTSignRequestDto cwtSignRequestDto = new CWTSignRequestDto();
        cwtSignRequestDto.setApplicationId("ID_REPO");
        cwtSignRequestDto.setReferenceId("EC_SECP256R1_SIGN");
        cwtSignRequestDto.setPayload(null);
        cwtSignRequestDto.setClaim169Payload("D83DD28445A101390100A053A3041A69BE65DC051A68D117DC061A68D117DC584603104DA01E36460ABC0A408985D760EEACE7FFC445E46F221FB2DCC2DE29E9388D2384F4B9A2C8FF6369A3AA2A82EBE532C763C780F1B3C87FCAD58B01A93B4099D281BC327C");
        
        CoseSignResponseDto response = coseSignatureService.cwtSign(cwtSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getSignedData());
    }

    @Test
    public void testCwtSignAndVerifyWithClaims() {
        Map<String, Object> protectedHeader = new HashMap<>();
        protectedHeader.put("crit", "kid, alg");
        protectedHeader.put("cty", "application/cbor");
        protectedHeader.put("includeCertificate", true);
        protectedHeader.put("kid", false);

        Map<String, Object> unprotectedHeader = new HashMap<>();
        unprotectedHeader.put("includeCertificateChain", true);
        unprotectedHeader.put("includeCertificateHash", true);
        unprotectedHeader.put("certificateUrl", "https://test.com/cert");
        unprotectedHeader.put("kid", true);
        unprotectedHeader.put("partial-iv", "njsancsalkjcaisjka");

        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ID_REPO");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setReferenceId("ED25519_SIGN");
        keymanagerService.generateECSignKey("CSR", keyPairGenRequestDto);

        CWTSignRequestDto cwtSignRequestDto = new CWTSignRequestDto();
        cwtSignRequestDto.setApplicationId("ID_REPO");
        cwtSignRequestDto.setReferenceId("ED25519_SIGN");
        cwtSignRequestDto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        cwtSignRequestDto.setIssuer("mosip");
        cwtSignRequestDto.setAudience("sonar Coverage");
        cwtSignRequestDto.setExpireDays(365);
        cwtSignRequestDto.setNotBeforeDays(0);
        cwtSignRequestDto.setProtectedHeader(protectedHeader);
        cwtSignRequestDto.setSubject("test case");
        cwtSignRequestDto.setUnprotectedHeader(unprotectedHeader);
        CoseSignResponseDto response = coseSignatureService.cwtSign(cwtSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getSignedData());

        CWTVerifyRequestDto cwtVerifyRequestDto = new CWTVerifyRequestDto();
        cwtVerifyRequestDto.setApplicationId("ID_REPO");
        cwtVerifyRequestDto.setReferenceId("ED25519_SIGN");
        cwtVerifyRequestDto.setIssuer("mosip");
        cwtVerifyRequestDto.setSubject("test case");
        cwtVerifyRequestDto.setValidateTrust(true);
        cwtVerifyRequestDto.setDomain("DEVICE");
        cwtVerifyRequestDto.setCoseSignedData(response.getSignedData());

        CoseSignVerifyResponseDto verifyResponse = coseSignatureService.cwtVerify(cwtVerifyRequestDto);
        Assert.assertNotNull(verifyResponse);
        Assert.assertTrue(verifyResponse.isSignatureValid());
        Assert.assertEquals("Validation Successful", verifyResponse.getMessage());
    }

    @Test(expected = RequestException.class)
    public void testCwtSignRequestException() {
        CWTSignRequestDto cwtSignRequestDto = new CWTSignRequestDto();
        cwtSignRequestDto.setApplicationId("INVALID_APP_ID");

        coseSignatureService.cwtSign(cwtSignRequestDto);

        cwtSignRequestDto.setApplicationId("TEST");
        cwtSignRequestDto.setPayload("");
        cwtSignRequestDto.setClaim169Payload("");
        coseSignatureService.cwtSign(cwtSignRequestDto);
    }

    @Test
    public void testCwtSignInvalidPayload() {
        CWTSignRequestDto cwtSignRequestDto = new CWTSignRequestDto();
        cwtSignRequestDto.setApplicationId("ID_REPO");
        cwtSignRequestDto.setReferenceId("");
        cwtSignRequestDto.setPayload("");
        cwtSignRequestDto.setClaim169Payload("");
        
        RequestException exception = assertThrows(RequestException.class, () -> {
            coseSignatureService.cwtSign(cwtSignRequestDto);
        });
        Assert.assertNotNull(exception);
    }

    @Test
    public void testCwtVerify() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ID_REPO");
        keyPairGenRequestDto.setReferenceId("EC_SECP256K1_SIGN");
        keymanagerService.generateECSignKey("CSR", keyPairGenRequestDto);
        // First sign the CWT
        CWTSignRequestDto cwtSignRequestDto = new CWTSignRequestDto();
        cwtSignRequestDto.setApplicationId("ID_REPO");
        cwtSignRequestDto.setReferenceId("EC_SECP256K1_SIGN");
        cwtSignRequestDto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        CoseSignResponseDto signResponse = coseSignatureService.cwtSign(cwtSignRequestDto);
        
        // Then verify it
        CWTVerifyRequestDto cwtVerifyRequestDto = new CWTVerifyRequestDto();
        cwtVerifyRequestDto.setApplicationId("ID_REPO");
        cwtVerifyRequestDto.setReferenceId("EC_SECP256K1_SIGN");
        cwtVerifyRequestDto.setCoseSignedData(signResponse.getSignedData());
        CoseSignVerifyResponseDto verifyResponse = coseSignatureService.cwtVerify(cwtVerifyRequestDto);
        
        Assert.assertNotNull(verifyResponse);
        Assert.assertTrue(verifyResponse.isSignatureValid());
        Assert.assertEquals("Validation Successful", verifyResponse.getMessage());
    }

    @Test
    public void testCwtVerifyInvalidData() {
        CWTVerifyRequestDto cwtVerifyRequestDto = new CWTVerifyRequestDto();
        cwtVerifyRequestDto.setCoseSignedData("invalid-hex-data");
        
        SignatureFailureException exception = assertThrows(SignatureFailureException.class, () -> {
            coseSignatureService.cwtVerify(cwtVerifyRequestDto);
        });
        Assert.assertNotNull(exception);
    }

    @Test
    public void testCwtVerifyEmptyData() {
        CWTVerifyRequestDto cwtVerifyRequestDto = new CWTVerifyRequestDto();
        cwtVerifyRequestDto.setCoseSignedData("");
        
        RequestException exception = assertThrows(RequestException.class, () -> {
            coseSignatureService.cwtVerify(cwtVerifyRequestDto);
        });
        Assert.assertNotNull(exception);
    }

    @Test(expected = RequestException.class)
    public void testCwtVerifyTag() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        CoseSignRequestDto coseSignRequestDto = new CoseSignRequestDto();
        coseSignRequestDto.setApplicationId("TEST");
        coseSignRequestDto.setReferenceId("");
        coseSignRequestDto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        CoseSignResponseDto response = coseSignatureService.coseSign1(coseSignRequestDto);

        CWTVerifyRequestDto cwtVerifyRequestDto = new CWTVerifyRequestDto();
        cwtVerifyRequestDto.setApplicationId("TEST");
        cwtVerifyRequestDto.setReferenceId("");
        cwtVerifyRequestDto.setCoseSignedData(response.getSignedData());
        coseSignatureService.cwtVerify(cwtVerifyRequestDto);

        cwtVerifyRequestDto.setCoseSignedData("D83DD38445A101390100A053A3041A69BE65DC051A68D117DC061A68D117DC584603104DA01E36460ABC0A408985D760EEACE7FFC445E46F221FB2DCC2DE29E9388D2384F4B9A2C8FF6369A3AA2A82EBE532C763C780F1B3C87FCAD58B01A93B4099D281BC327C");
        coseSignatureService.cwtVerify(cwtVerifyRequestDto);
    }

    @Test(expected = RequestException.class)
    public void testCWTVerifyChecksException() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        CWTSignRequestDto cwtSignRequestDto = new CWTSignRequestDto();
        cwtSignRequestDto.setApplicationId("TEST");
        cwtSignRequestDto.setReferenceId("");
        cwtSignRequestDto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        cwtSignRequestDto.setIssuer("keymgr");
        cwtSignRequestDto.setExpireDays(365);
        cwtSignRequestDto.setNotBeforeDays(2);
        cwtSignRequestDto.setSubject("test case");
        CoseSignResponseDto response = coseSignatureService.cwtSign(cwtSignRequestDto);

        CWTVerifyRequestDto cwtVerifyRequestDto = new CWTVerifyRequestDto();
        cwtVerifyRequestDto.setApplicationId("TEST");
        cwtVerifyRequestDto.setReferenceId("");
        cwtVerifyRequestDto.setCoseSignedData(response.getSignedData());
        coseSignatureService.cwtVerify(cwtVerifyRequestDto);

        cwtSignRequestDto.setNotBeforeDays(0);
        cwtSignRequestDto.setExpireDays(0);
        response = coseSignatureService.cwtSign(cwtSignRequestDto);

        cwtVerifyRequestDto.setCoseSignedData(response.getSignedData());
        coseSignatureService.cwtVerify(cwtVerifyRequestDto);

        cwtSignRequestDto.setExpireDays(365);
        response = coseSignatureService.cwtSign(cwtSignRequestDto);

        cwtVerifyRequestDto.setCoseSignedData(response.getSignedData());
        coseSignatureService.cwtVerify(cwtVerifyRequestDto);

        cwtVerifyRequestDto.setIssuer("invalid-issuer");
        coseSignatureService.cwtVerify(cwtVerifyRequestDto);

        cwtVerifyRequestDto.setSubject("invalid-subject");
        coseSignatureService.cwtVerify(cwtVerifyRequestDto);
    }

    @Test
    public void testCoseSign1WithPS256Algorithm() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("REGISTRATION");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        CoseSignRequestDto coseSignRequestDto = new CoseSignRequestDto();
        coseSignRequestDto.setApplicationId("REGISTRATION");
        coseSignRequestDto.setReferenceId("");
        coseSignRequestDto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        coseSignRequestDto.setAlgorithm("PS256");
        
        CoseSignResponseDto response = coseSignatureService.coseSign1(coseSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getSignedData());
    }

    @Test
    public void testCoseSign1WithES256KAlgorithm() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("REGISTRATION");
        keyPairGenRequestDto.setReferenceId("EC_SECP256K1_SIGN");
        keymanagerService.generateECSignKey("CSR", keyPairGenRequestDto);

        CoseSignRequestDto coseSignRequestDto = new CoseSignRequestDto();
        coseSignRequestDto.setApplicationId("REGISTRATION");
        coseSignRequestDto.setReferenceId("EC_SECP256K1_SIGN");
        coseSignRequestDto.setAlgorithm("ES256K");
        coseSignRequestDto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        
        CoseSignResponseDto response = coseSignatureService.coseSign1(coseSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getSignedData());
    }
}