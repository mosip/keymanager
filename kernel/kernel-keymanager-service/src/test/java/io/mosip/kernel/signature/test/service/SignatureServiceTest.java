package io.mosip.kernel.signature.test.service;

import io.mosip.kernel.core.crypto.exception.SignatureException;
import io.mosip.kernel.core.signatureutil.model.SignatureResponse;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils2;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerErrorConstant;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.signature.constant.SignatureConstant;
import io.mosip.kernel.signature.constant.SignatureErrorCode;
import io.mosip.kernel.signature.dto.*;
import io.mosip.kernel.signature.exception.RequestException;
import io.mosip.kernel.signature.exception.SignatureFailureException;
import io.mosip.kernel.signature.service.SignatureProvider;
import io.mosip.kernel.signature.service.SignatureService;
import io.mosip.kernel.signature.service.SignatureServicev2;
import io.mosip.kernel.signature.service.impl.EC256SignatureProviderImpl;
import io.mosip.kernel.signature.service.impl.Ed25519SignatureProviderImpl;
import io.mosip.kernel.signature.service.impl.PS256SIgnatureProviderImpl;
import io.mosip.kernel.signature.service.impl.RS256SignatureProviderImpl;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;


@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
public class SignatureServiceTest {

    @Autowired
    private SignatureService signatureService;

    @Autowired
    private SignatureServicev2 signatureServicev2;

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private KeyAliasRepository keyAliasRepository;

    @Autowired
    KeymanagerUtil keymanagerUtil;

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

    private static Map<String, SignatureProvider> SIGNATURE_PROVIDER = new HashMap<>();

    static {
        SIGNATURE_PROVIDER.put(SignatureConstant.JWS_PS256_SIGN_ALGO_CONST, new PS256SIgnatureProviderImpl());
        SIGNATURE_PROVIDER.put(SignatureConstant.JWS_RS256_SIGN_ALGO_CONST, new RS256SignatureProviderImpl());
        SIGNATURE_PROVIDER.put(SignatureConstant.JWS_ES256_SIGN_ALGO_CONST, new EC256SignatureProviderImpl());
        SIGNATURE_PROVIDER.put(SignatureConstant.JWS_ES256K_SIGN_ALGO_CONST, new EC256SignatureProviderImpl());
        SIGNATURE_PROVIDER.put(SignatureConstant.JWS_EDDSA_SIGN_ALGO_CONST, new Ed25519SignatureProviderImpl());
    }

    @Test
    public void testJwtSign() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        JWTSignatureRequestDto jwtSignRequestDto = new JWTSignatureRequestDto();
        jwtSignRequestDto.setApplicationId("TEST");
        jwtSignRequestDto.setReferenceId("");
        jwtSignRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes()));
        jwtSignRequestDto.setIncludePayload(true);
        jwtSignRequestDto.setIncludeCertificate(true);
        jwtSignRequestDto.setIncludeCertHash(true);
        jwtSignRequestDto.setCertificateUrl("https://test.com/cert");

        JWTSignatureResponseDto response = signatureService.jwtSign(jwtSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getJwtSignedData());
        Assert.assertNotNull(response.getTimestamp());

        jwtSignRequestDto.setApplicationId(null);
        jwtSignRequestDto.setReferenceId(null);
        jwtSignRequestDto.setIncludePayload(false);
        jwtSignRequestDto.setIncludeCertificate(false);
        jwtSignRequestDto.setIncludeCertHash(false);
        response = signatureService.jwtSign(jwtSignRequestDto);
        Assert.assertNotNull(response);
    }

    @Test
    public void testJwtSignWithKernelSign() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        JWTSignatureRequestDto jwtSignRequestDto = new JWTSignatureRequestDto();
        jwtSignRequestDto.setApplicationId("KERNEL");
        jwtSignRequestDto.setReferenceId("SIGN");
        jwtSignRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes()));
        jwtSignRequestDto.setIncludePayload(false);
        jwtSignRequestDto.setCertificateUrl("https://test.com/cert");

        JWTSignatureResponseDto response = signatureService.jwtSign(jwtSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getJwtSignedData());
    }

    @Test
    public void testJwtSignWithECKey() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("EC_SECP256R1_SIGN");
        keymanagerService.generateECSignKey("CSR", keyPairGenRequestDto);

        JWTSignatureRequestDto jwtSignRequestDto = new JWTSignatureRequestDto();
        jwtSignRequestDto.setApplicationId("TEST");
        jwtSignRequestDto.setReferenceId("EC_SECP256R1_SIGN");
        jwtSignRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes()));

        JWTSignatureResponseDto response = signatureService.jwtSign(jwtSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getJwtSignedData());
    }

    @Test
    public void testJwtSignWithEd25519Key() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("ED25519_SIGN");
        keymanagerService.generateECSignKey("CSR", keyPairGenRequestDto);

        JWTSignatureRequestDto jwtSignRequestDto = new JWTSignatureRequestDto();
        jwtSignRequestDto.setApplicationId("TEST");
        jwtSignRequestDto.setReferenceId("ED25519_SIGN");
        jwtSignRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes()));

        JWTSignatureResponseDto response = signatureService.jwtSign(jwtSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getJwtSignedData());
    }

    @Test(expected = RequestException.class)
    public void testJwtSignInvalidAccess() {
        JWTSignatureRequestDto jwtSignRequestDto = new JWTSignatureRequestDto();
        jwtSignRequestDto.setApplicationId("INVALID_APP_ID");
        jwtSignRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes()));
        signatureService.jwtSign(jwtSignRequestDto);
    }

    @Test(expected = RequestException.class)
    public void testJwtSignInvalidData() {
        JWTSignatureRequestDto jwtSignRequestDto = new JWTSignatureRequestDto();
        jwtSignRequestDto.setApplicationId("TEST");
        jwtSignRequestDto.setDataToSign("");
        signatureService.jwtSign(jwtSignRequestDto);
    }

    @Test(expected = RequestException.class)
    public void testJwtSignInvalidJson() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        JWTSignatureRequestDto jwtSignRequestDto = new JWTSignatureRequestDto();
        jwtSignRequestDto.setApplicationId("TEST");
        jwtSignRequestDto.setReferenceId("");
        jwtSignRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("invalid json".getBytes()));
        signatureService.jwtSign(jwtSignRequestDto);
    }

    @Test
    public void testJwtVerify() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        // First sign
        JWTSignatureRequestDto jwtSignRequestDto = new JWTSignatureRequestDto();
        jwtSignRequestDto.setApplicationId("TEST");
        jwtSignRequestDto.setReferenceId("");
        jwtSignRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes()));
        jwtSignRequestDto.setIncludePayload(true);
        jwtSignRequestDto.setIncludeCertificate(true);
        JWTSignatureResponseDto signResponse = signatureService.jwtSign(jwtSignRequestDto);

        // Then verify
        JWTSignatureVerifyRequestDto verifyRequestDto = new JWTSignatureVerifyRequestDto();
        verifyRequestDto.setApplicationId("TEST");
        verifyRequestDto.setReferenceId("");
        verifyRequestDto.setJwtSignatureData(signResponse.getJwtSignedData());
        JWTSignatureVerifyResponseDto verifyResponse = signatureService.jwtVerify(verifyRequestDto);

        Assert.assertNotNull(verifyResponse);
        Assert.assertTrue(verifyResponse.isSignatureValid());
        Assert.assertEquals("Validation Successful", verifyResponse.getMessage());

        keyPairGenRequestDto.setReferenceId("ED25519_SIGN");
        keymanagerService.generateECSignKey("CSR", keyPairGenRequestDto);
        jwtSignRequestDto.setReferenceId("ED25519_SIGN");
        signResponse = signatureService.jwtSign(jwtSignRequestDto);
        verifyRequestDto.setJwtSignatureData(signResponse.getJwtSignedData());
        verifyResponse = signatureService.jwtVerify(verifyRequestDto);

        Assert.assertNotNull(verifyResponse);
    }

    @Test
    public void testJwtVerifyWithDetachedPayload() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        String payload = CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes());

        // Sign with detached payload
        JWTSignatureRequestDto jwtSignRequestDto = new JWTSignatureRequestDto();
        jwtSignRequestDto.setApplicationId("TEST");
        jwtSignRequestDto.setReferenceId("");
        jwtSignRequestDto.setDataToSign(payload);
        jwtSignRequestDto.setIncludePayload(false);
        JWTSignatureResponseDto signResponse = signatureService.jwtSign(jwtSignRequestDto);

        // Verify with actual data
        JWTSignatureVerifyRequestDto verifyRequestDto = new JWTSignatureVerifyRequestDto();
        verifyRequestDto.setApplicationId("TEST");
        verifyRequestDto.setReferenceId("");
        verifyRequestDto.setJwtSignatureData(signResponse.getJwtSignedData());
        verifyRequestDto.setActualData(payload);
        JWTSignatureVerifyResponseDto verifyResponse = signatureService.jwtVerify(verifyRequestDto);

        Assert.assertNotNull(verifyResponse);
        Assert.assertTrue(verifyResponse.isSignatureValid());
    }

    @Test
    public void testJwtVerifyWithTrustValidation() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        JWTSignatureRequestDto jwtSignRequestDto = new JWTSignatureRequestDto();
        jwtSignRequestDto.setApplicationId("TEST");
        jwtSignRequestDto.setReferenceId("");
        jwtSignRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes()));
        jwtSignRequestDto.setIncludeCertificate(true);
        JWTSignatureResponseDto signResponse = signatureService.jwtSign(jwtSignRequestDto);

        JWTSignatureVerifyRequestDto verifyRequestDto = new JWTSignatureVerifyRequestDto();
        verifyRequestDto.setApplicationId("TEST");
        verifyRequestDto.setReferenceId("");
        verifyRequestDto.setJwtSignatureData(signResponse.getJwtSignedData());
        verifyRequestDto.setValidateTrust(true);
        verifyRequestDto.setDomain("DEVICE");
        JWTSignatureVerifyResponseDto verifyResponse = signatureService.jwtVerify(verifyRequestDto);

        Assert.assertNotNull(verifyResponse);
        Assert.assertNotNull(verifyResponse.getTrustValid());
    }

    @Test(expected = RequestException.class)
    public void testJwtVerifyInvalidData() {
        JWTSignatureVerifyRequestDto verifyRequestDto = new JWTSignatureVerifyRequestDto();
        verifyRequestDto.setJwtSignatureData("");
        signatureService.jwtVerify(verifyRequestDto);
    }

    @Test
    public void testJwsSign() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        JWSSignatureRequestDto jwsSignRequestDto = new JWSSignatureRequestDto();
        jwsSignRequestDto.setApplicationId("TEST");
        jwsSignRequestDto.setReferenceId("");
        jwsSignRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes()));
        jwsSignRequestDto.setIncludePayload(true);
        jwsSignRequestDto.setIncludeCertificate(true);
        jwsSignRequestDto.setB64JWSHeaderParam(false);
        jwsSignRequestDto.setValidateJson(true);

        JWTSignatureResponseDto response = signatureService.jwsSign(jwsSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getJwtSignedData());

        jwsSignRequestDto.setApplicationId("KERNEL");
        jwsSignRequestDto.setReferenceId("SIGN");
        jwsSignRequestDto.setIncludePayload(false);
        jwsSignRequestDto.setIncludeCertificate(false);
        jwsSignRequestDto.setB64JWSHeaderParam(true);
        jwsSignRequestDto.setCertificateUrl("https:://test/certificate.com");
        response = signatureService.jwsSign(jwsSignRequestDto);
        Assert.assertNotNull(response);

        jwsSignRequestDto.setApplicationId("");
        response = signatureService.jwsSign(jwsSignRequestDto);
        Assert.assertNotNull(response);

        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("ED25519_SIGN");
        keymanagerService.generateECSignKey("CSR", keyPairGenRequestDto);
        jwsSignRequestDto.setApplicationId("TEST");
        jwsSignRequestDto.setReferenceId("ED25519_SIGN");
        response = signatureService.jwsSign(jwsSignRequestDto);
        Assert.assertNotNull(response);
    }

    @Test
    public void testJwsSignWithB64Header() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        JWSSignatureRequestDto jwsSignRequestDto = new JWSSignatureRequestDto();
        jwsSignRequestDto.setApplicationId("TEST");
        jwsSignRequestDto.setReferenceId("");
        jwsSignRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes()));
        jwsSignRequestDto.setB64JWSHeaderParam(true);
        jwsSignRequestDto.setValidateJson(true);

        JWTSignatureResponseDto response = signatureService.jwsSign(jwsSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getJwtSignedData());
    }

    @Test(expected = RequestException.class)
    public void testJwsSignInvalidAccess() {
        JWSSignatureRequestDto jwsSignRequestDto = new JWSSignatureRequestDto();
        jwsSignRequestDto.setApplicationId("INVALID_APP_ID");
        jwsSignRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes()));
        signatureService.jwsSign(jwsSignRequestDto);
    }

    @Test(expected = RequestException.class)
    public void testJwsSignInvalidJson() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        JWSSignatureRequestDto jwsSignRequestDto = new JWSSignatureRequestDto();
        jwsSignRequestDto.setApplicationId("TEST");
        jwsSignRequestDto.setReferenceId("");
        jwsSignRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("invalid json".getBytes()));
        jwsSignRequestDto.setValidateJson(true);
        signatureService.jwsSign(jwsSignRequestDto);
    }

    @Test
    public void testSignv2() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        SignRequestDtoV2 signRequestDto = new SignRequestDtoV2();
        signRequestDto.setApplicationId("TEST");
        signRequestDto.setReferenceId("");
        signRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("test data".getBytes()));
        signRequestDto.setSignAlgorithm("PS256");
        signRequestDto.setResponseEncodingFormat("base64url");

        SignResponseDto response = signatureServicev2.signv2(signRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getSignature());
        Assert.assertNotNull(response.getTimestamp());

        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        signRequestDto.setApplicationId("");
        response = signatureServicev2.signv2(signRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getSignature());
    }

    @Test
    public void testSignv2WithBase58BTC() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        SignRequestDtoV2 signRequestDto = new SignRequestDtoV2();
        signRequestDto.setApplicationId("TEST");
        signRequestDto.setReferenceId("");
        signRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("test data".getBytes()));
        signRequestDto.setResponseEncodingFormat("base58btc");

        SignResponseDto response = signatureServicev2.signv2(signRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getSignature());
    }

    @Test(expected = KeymanagerServiceException.class)
    public void testSignv2InvalidFormat() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        SignRequestDtoV2 signRequestDto = new SignRequestDtoV2();
        signRequestDto.setApplicationId("TEST");
        signRequestDto.setReferenceId("");
        signRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("test data".getBytes()));
        signRequestDto.setResponseEncodingFormat("invalid");
        signatureServicev2.signv2(signRequestDto);
    }

    @Test
    public void testRawSign() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        SignRequestDtoV2 signRequestDto = new SignRequestDtoV2();
        signRequestDto.setApplicationId("TEST");
        signRequestDto.setReferenceId("");
        signRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("test data".getBytes()));
        signRequestDto.setSignAlgorithm("PS256");

        SignResponseDtoV2 response = signatureServicev2.rawSign(signRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getSignedData());
        Assert.assertNotNull(response.getCertificate());
        Assert.assertNotNull(response.getSignatureAlgorithm());
        Assert.assertNotNull(response.getKeyId());
    }

    @Test
    public void testJwtSignV2() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ADMIN_SERVICES");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        JWTSignatureRequestDtoV2 jwtSignRequestDto = new JWTSignatureRequestDtoV2();
        jwtSignRequestDto.setApplicationId("ADMIN_SERVICES");
        jwtSignRequestDto.setReferenceId("");
        jwtSignRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes()));
        jwtSignRequestDto.setIncludePayload(true);
        jwtSignRequestDto.setIncludeCertificateChain(false);
        jwtSignRequestDto.setIncludeCertHash(true);

        Map<String, String> additionalHeaders = new HashMap<>();
        additionalHeaders.put("custom", "header");
        jwtSignRequestDto.setAdditionalHeaders(additionalHeaders);

        JWTSignatureResponseDto response = signatureService.jwtSignV2(jwtSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getJwtSignedData());

        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        jwtSignRequestDto.setApplicationId(null);
        jwtSignRequestDto.setReferenceId(null);
        response = signatureService.jwtSignV2(jwtSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getJwtSignedData());

        Map<String, String> additionalHeaders2 = new HashMap<>();
        additionalHeaders2.put("test", "header");
        additionalHeaders2.put("kid", "test");
        additionalHeaders2.put("aud", "test");
        jwtSignRequestDto.setAdditionalHeaders(additionalHeaders2);
        response = signatureService.jwtSignV2(jwtSignRequestDto);
        Assert.assertNotNull(response);
    }

    @Test
    public void testSignPDF() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        PDFSignatureRequestDto pdfSignRequestDto = new PDFSignatureRequestDto();
        pdfSignRequestDto.setApplicationId("TEST");
        pdfSignRequestDto.setReferenceId("");
        pdfSignRequestDto.setData(CryptoUtil.encodeToURLSafeBase64("dummy pdf content".getBytes()));
        pdfSignRequestDto.setTimeStamp(DateUtils2.getUTCCurrentDateTimeString());
        pdfSignRequestDto.setReason("Test signing");
        pdfSignRequestDto.setPageNumber(1);
        pdfSignRequestDto.setLowerLeftX(100);
        pdfSignRequestDto.setLowerLeftY(100);
        pdfSignRequestDto.setUpperRightX(200);
        pdfSignRequestDto.setUpperRightY(200);
        pdfSignRequestDto.setPassword("test123");

        try {
            SignatureResponseDto response = signatureService.signPDF(pdfSignRequestDto);
            Assert.assertNotNull(response);
        } catch (Exception e) {
            // PDF signing may fail due to invalid PDF content, but we test the flow
            Assert.assertTrue(e instanceof KeymanagerServiceException);
        }
    }

    @Test
    public void testValidateTrust() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        JWTSignatureVerifyRequestDto jwtVerifyRequestDto = new JWTSignatureVerifyRequestDto();
        jwtVerifyRequestDto.setValidateTrust(false);

        String trustResult = signatureService.validateTrust(jwtVerifyRequestDto, null);
        Assert.assertEquals("TRUST_NOT_VERIFIED", trustResult);

        jwtVerifyRequestDto.setValidateTrust(true);
        trustResult = signatureService.validateTrust(jwtVerifyRequestDto, null);
        Assert.assertEquals("TRUST_NOT_VERIFIED_NO_DOMAIN", trustResult);
    }

    @Test
    public void testEcdsaSECP256K1Algorithm() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("EC_SECP256K1_SIGN");
        keymanagerService.generateECSignKey("CSR", keyPairGenRequestDto);

        JWTSignatureRequestDto jwtSignRequestDto = new JWTSignatureRequestDto();
        jwtSignRequestDto.setApplicationId("TEST");
        jwtSignRequestDto.setReferenceId("EC_SECP256K1_SIGN");
        jwtSignRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes()));

        JWTSignatureResponseDto response = signatureService.jwtSign(jwtSignRequestDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getJwtSignedData());
    }

    @Test
    public void testSign() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        SignRequestDto signRequestDto = new SignRequestDto();
        signRequestDto.setData("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        SignatureResponse response = signatureService.sign(signRequestDto);
        Assert.assertNotNull(response);
    }

//    @Test
//    public void testValidate() {
//        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
//        keyPairGenRequestDto.setApplicationId("KERNEL");
//        keyPairGenRequestDto.setReferenceId("SIGN");
//        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
//
//        SignRequestDto signRequestDto = new SignRequestDto();
//        signRequestDto.setData("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
//        SignatureResponse signResponse = signatureService.sign(signRequestDto);
//
//        TimestampRequestDto timestampRequestDto = new TimestampRequestDto();
//        timestampRequestDto.setSignature(signResponse.getData());
//        timestampRequestDto.setData("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
//        timestampRequestDto.setTimestamp(DateUtils2.getUTCCurrentDateTime());
//        ValidatorResponseDto response = signatureService.validate(timestampRequestDto);
//        Assert.assertNotNull(response);
//        Assert.assertEquals("success", response.getStatus());
//    }

//    @Test(expected = SignatureException.class)
//    public void testValidateException() {
//        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
//        keyPairGenRequestDto.setApplicationId("KERNEL");
//        keyPairGenRequestDto.setReferenceId("SIGN");
//        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
//
//        TimestampRequestDto timestampRequestDto = new TimestampRequestDto();
//        timestampRequestDto.setData("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
//        timestampRequestDto.setSignature("invalid signature");
//        timestampRequestDto.setTimestamp(DateUtils2.getUTCCurrentDateTime());
//        signatureService.validate(timestampRequestDto);
//    }

    @Test(expected = SignatureFailureException.class)
    public void testPS256Exception() {
        SignatureProvider signatureProvider = SIGNATURE_PROVIDER.get("PS256");
        signatureProvider.sign(null, null, "Invalid Provider");
    }

    @Test(expected = SignatureFailureException.class)
    public void testRS256Exception() {
        SignatureProvider signatureProvider = SIGNATURE_PROVIDER.get("RS256");
        signatureProvider.sign(null, null, "Invalid Provider");
    }

    @Test(expected = SignatureFailureException.class)
    public void testEC256Exception() {
        SignatureProvider signatureProvider = SIGNATURE_PROVIDER.get("ES256");
        signatureProvider.sign(null, null, "Invalid Provider");
    }

    @Test(expected = SignatureFailureException.class)
    public void testEd25519Exception() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        SignatureProvider signatureProvider = SIGNATURE_PROVIDER.get("EdDSA");
        signatureProvider.sign(keyPair.getPrivate(), null, "Invalid Provider");
    }

    @Test
    public void testValidateTrustV2() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        JWTSignatureVerifyRequestDto jwtVerifyRequestDto = new JWTSignatureVerifyRequestDto();
        jwtVerifyRequestDto.setValidateTrust(false);

        String trustResult = signatureService.validateTrustV2(jwtVerifyRequestDto, null, null);
        Assert.assertEquals("TRUST_NOT_VERIFIED", trustResult);

        jwtVerifyRequestDto.setValidateTrust(true);
        String pemCertificate = keymanagerService.getCertificate("TEST", Optional.empty()).getCertificate();
        List<Certificate> certificateList = new ArrayList<>(Collections.singleton(keymanagerUtil.convertToCertificate(pemCertificate)));
        trustResult = signatureService.validateTrustV2(jwtVerifyRequestDto, certificateList, pemCertificate);
        Assert.assertEquals("TRUST_NOT_VERIFIED_NO_DOMAIN", trustResult);

        jwtVerifyRequestDto.setDomain("DEVICE");
        trustResult = signatureService.validateTrustV2(jwtVerifyRequestDto, certificateList, pemCertificate);
        Assert.assertEquals("TRUST_CERT_PATH_NOT_VALID", trustResult);
    }

    @Test
    public void testJwtVerifyV2() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        // First sign
        JWTSignatureRequestDtoV2 jwtSignRequestDtoV2 = new JWTSignatureRequestDtoV2();
        jwtSignRequestDtoV2.setApplicationId("TEST");
        jwtSignRequestDtoV2.setReferenceId("");
        jwtSignRequestDtoV2.setDataToSign(CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes()));
        jwtSignRequestDtoV2.setIncludePayload(true);
        jwtSignRequestDtoV2.setIncludeCertificateChain(true);
        jwtSignRequestDtoV2.setIncludeCertHash(true);
        jwtSignRequestDtoV2.setCertificateUrl("https://test.com/cert");
        JWTSignatureResponseDto signResponse = signatureService.jwtSignV2(jwtSignRequestDtoV2);

        // Then verify
        JWTSignatureVerifyRequestDto verifyRequestDto = new JWTSignatureVerifyRequestDto();
        verifyRequestDto.setApplicationId("TEST");
        verifyRequestDto.setReferenceId("");
        verifyRequestDto.setJwtSignatureData(signResponse.getJwtSignedData());
        JWTSignatureVerifyResponseDto verifyResponse = signatureService.jwtVerifyV2(verifyRequestDto);

        Assert.assertNotNull(verifyResponse);
        Assert.assertTrue(verifyResponse.isSignatureValid());
        Assert.assertEquals("Validation Successful", verifyResponse.getMessage());

        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        jwtSignRequestDtoV2.setApplicationId("");
        jwtSignRequestDtoV2.setReferenceId("");
        jwtSignRequestDtoV2.setIncludeCertificateChain(false);
        signResponse = signatureService.jwtSignV2(jwtSignRequestDtoV2);

        verifyRequestDto.setJwtSignatureData(signResponse.getJwtSignedData());
        verifyRequestDto.setApplicationId("");
        verifyResponse = signatureService.jwtVerifyV2(verifyRequestDto);
        Assert.assertNotNull(verifyResponse);
        Assert.assertTrue(verifyResponse.isSignatureValid());
        Assert.assertEquals("Validation Successful", verifyResponse.getMessage());
    }

    @Test
    public void testJwsSignV2() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        Map<String, String> addtionalHeader = new HashMap<>();
        addtionalHeader.put("test", "header");
        addtionalHeader.put("test2", "header2");
        addtionalHeader.put("iss", "test");
        addtionalHeader.put("aud", "test");
        addtionalHeader.put("sub", "test");

        JWSSignatureRequestDtoV2 jwsSignRequestDtoV2 = new JWSSignatureRequestDtoV2();
        jwsSignRequestDtoV2.setApplicationId("TEST");
        jwsSignRequestDtoV2.setReferenceId("");
        jwsSignRequestDtoV2.setDataToSign(CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes()));
        jwsSignRequestDtoV2.setIncludePayload(true);
        jwsSignRequestDtoV2.setIncludeCertificateChain(true);
        jwsSignRequestDtoV2.setB64JWSHeaderParam(false);
        jwsSignRequestDtoV2.setValidateJson(true);
        jwsSignRequestDtoV2.setAdditionalHeaders(addtionalHeader);

        JWTSignatureResponseDto response = signatureService.jwsSignV2(jwsSignRequestDtoV2);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getJwtSignedData());

        jwsSignRequestDtoV2.setApplicationId("KERNEL");
        jwsSignRequestDtoV2.setReferenceId("SIGN");
        jwsSignRequestDtoV2.setIncludePayload(false);
        jwsSignRequestDtoV2.setIncludeCertificateChain(false);
        jwsSignRequestDtoV2.setB64JWSHeaderParam(true);
        jwsSignRequestDtoV2.setCertificateUrl("https:://test/certificate.com");
        response = signatureService.jwsSignV2(jwsSignRequestDtoV2);
        Assert.assertNotNull(response);

        jwsSignRequestDtoV2.setApplicationId("");
        response = signatureService.jwsSignV2(jwsSignRequestDtoV2);
        Assert.assertNotNull(response);

        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("ED25519_SIGN");
        keymanagerService.generateECSignKey("CSR", keyPairGenRequestDto);

        jwsSignRequestDtoV2.setApplicationId("TEST");
        jwsSignRequestDtoV2.setReferenceId("ED25519_SIGN");
        response = signatureService.jwsSignV2(jwsSignRequestDtoV2);
        Assert.assertNotNull(response);
    }

    @Test
    public void testJwtVerifyDefaultAppIDAndRefID() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        // First sign
        JWTSignatureRequestDto jwtSignRequestDto = new JWTSignatureRequestDto();
        jwtSignRequestDto.setDataToSign(CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes()));
        jwtSignRequestDto.setIncludePayload(true);
        jwtSignRequestDto.setIncludeCertificate(false);
        JWTSignatureResponseDto signResponse = signatureService.jwtSign(jwtSignRequestDto);

        // Then verify
        JWTSignatureVerifyRequestDto verifyRequestDto = new JWTSignatureVerifyRequestDto();
        verifyRequestDto.setJwtSignatureData(signResponse.getJwtSignedData());
        JWTSignatureVerifyResponseDto verifyResponse = signatureService.jwtVerify(verifyRequestDto);

        Assert.assertNotNull(verifyResponse);
        Assert.assertTrue(verifyResponse.isSignatureValid());
        Assert.assertEquals("Validation Successful", verifyResponse.getMessage());
    }

    @Test
    public void testJsonParsingError() {
        String signData = "ewogICJhbGciOiAiUlMyNTYiLAogIHg1YzogWwogICAgIlNmN21UV2pmOE91VWlVTksybXNYTXN2SEZhdjlmaGJJNkNvVlhyUlJPY0xPVFZrNk9lSSsrckZaQ0w4NDZsSk82MlpRTHZuZSs2IgogIF0sCiAgImtpZCI6ICJNQ1NTSjZBdjhiV0FZNzBXUk5nNHVPS04yLUhFMGRGOW1pWUI3Q2lqT1BzIgp9.eyAibW9kdWxlIjogIktleW1hbmFnZXIiLCAicHJvamVjdCI6ICJNb3NpcCIgfQ.bZIrGgpKoZAsL0NyKKshS78LzlvLp3xdlWiHtrB---UVL0cAenbMaxrjgWphQAzH4l2NCOz7BYeL1UN1sUvMOBCNfplRaG8aEDb4TTG6aQjMRXZg7LJJnuBQjuU4pdPLa8qYMBhW5nssc-WZ9DK4aLH2YW68FF4zUezvAsJWexftNkVE0n9Vf05sxI4olVh696t-xrNFsMDHlrHyOWVzkQOI6i9OMsyOqgBdo6hNJG7DXTzPRV_xKkiR3SGRP0AmF57zvS7kQm8SwkGQQE9rGYPqkLG1x_3pHL4P9NeqTT77kIcKR22lOyeWKcKR1NSzmDA_RKbJBD_w9kHF0hdytg";
        JWTSignatureVerifyRequestDto verifyRequestDto = new JWTSignatureVerifyRequestDto();
        verifyRequestDto.setJwtSignatureData(signData);

        RequestException exception = assertThrows(RequestException.class, () -> {
            signatureService.jwtVerify(verifyRequestDto);
        });
        assertEquals(SignatureErrorCode.INVALID_VERIFY_INPUT.getErrorCode(), exception.getErrorCode());

        exception = assertThrows(RequestException.class, () -> {
            signatureService.jwtVerifyV2(verifyRequestDto);
        });
        assertEquals(SignatureErrorCode.INVALID_VERIFY_INPUT.getErrorCode(), exception.getErrorCode());
    }

    @Test
    public void testJWSsignEmptyDataException() {
        JWTSignatureRequestDto requestDto = new JWTSignatureRequestDto();
        requestDto.setDataToSign("");

        RequestException exception = assertThrows(RequestException.class, () -> {
            signatureService.jwtSign(requestDto);
        });

        assertEquals(SignatureErrorCode.INVALID_INPUT.getErrorCode(), exception.getErrorCode());
    }

    @Test
    public void testSignV2EmptyDataException() {
        SignRequestDtoV2 requestDto = new SignRequestDtoV2();
        requestDto.setApplicationId("INVALID_APP_ID");

        RequestException exception = assertThrows(RequestException.class, () -> {
            signatureServicev2.signv2(requestDto);
        });

        assertEquals(SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorCode(), exception.getErrorCode());

        requestDto.setApplicationId("TEST");
        exception = assertThrows(RequestException.class, () -> {
            signatureServicev2.signv2(requestDto);
        });
        assertEquals(SignatureErrorCode.INVALID_INPUT.getErrorCode(), exception.getErrorCode());
    }

    @Test
    public void rawSignException() {
        SignRequestDtoV2 requestDto = new SignRequestDtoV2();
        requestDto.setApplicationId("INVALID_APP_ID");

        RequestException exception = assertThrows(RequestException.class, () -> {
            signatureServicev2.rawSign(requestDto);
        });

        assertEquals(SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorCode(), exception.getErrorCode());

        requestDto.setApplicationId("TEST");
        exception = assertThrows(RequestException.class, () -> {
            signatureServicev2.rawSign(requestDto);
        });

        assertEquals(SignatureErrorCode.INVALID_INPUT.getErrorCode(), exception.getErrorCode());


        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        requestDto.setApplicationId(null);
        requestDto.setDataToSign("c2lnbiByYXcgZGF0YQ==");
        requestDto.setResponseEncodingFormat("INVALID_FORMAT");
        KeymanagerServiceException exception1 = assertThrows(KeymanagerServiceException.class, () -> {
            signatureServicev2.rawSign(requestDto);
        });
        assertEquals(KeymanagerErrorConstant.INVALID_FORMAT_ERROR.getErrorCode(), exception1.getErrorCode());

        requestDto.setResponseEncodingFormat("base64url");
        SignResponseDtoV2 response = signatureServicev2.rawSign(requestDto);
        Assert.assertNotNull(response);
    }

    @Test
    public void testJWTSignV2Exception() {
        JWTSignatureRequestDtoV2 requestDtoV2 = new JWTSignatureRequestDtoV2();
        requestDtoV2.setApplicationId("INVALID_APP_ID");

        RequestException exception = assertThrows(RequestException.class, () -> {
            signatureService.jwtSignV2(requestDtoV2);
        });

        assertEquals(SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorCode(), exception.getErrorCode());

        requestDtoV2.setApplicationId("TEST");
        exception = assertThrows(RequestException.class, () -> {
            signatureService.jwtSignV2(requestDtoV2);
        });
        assertEquals(SignatureErrorCode.INVALID_INPUT.getErrorCode(), exception.getErrorCode());

        requestDtoV2.setDataToSign("c2lnbiByYXcgZGF0YQ==");
        exception = assertThrows(RequestException.class, () -> {
            signatureService.jwtSignV2(requestDtoV2);
        });
        assertEquals(SignatureErrorCode.INVALID_JSON.getErrorCode(), exception.getErrorCode());
    }

    @Test
    public void testJWSsignV2Exception() {
        JWSSignatureRequestDtoV2 requestDtoV2 = new JWSSignatureRequestDtoV2();
        requestDtoV2.setApplicationId("INVALID_APP_ID");

        RequestException exception = assertThrows(RequestException.class, () -> {
            signatureService.jwsSignV2(requestDtoV2);
        });

        assertEquals(SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorCode(), exception.getErrorCode());

        requestDtoV2.setApplicationId("TEST");
        exception = assertThrows(RequestException.class, () -> {
            signatureService.jwsSignV2(requestDtoV2);
        });
        assertEquals(SignatureErrorCode.INVALID_INPUT.getErrorCode(), exception.getErrorCode());

        requestDtoV2.setDataToSign("c2lnbiByYXcgZGF0YQ==");
        requestDtoV2.setValidateJson(true);
        exception = assertThrows(RequestException.class, () -> {
            signatureService.jwsSignV2(requestDtoV2);
        });
        assertEquals(SignatureErrorCode.INVALID_JSON.getErrorCode(), exception.getErrorCode());
    }

    @Test
    public void testJWTVerifyV2EmptySignData() {
        JWTSignatureVerifyRequestDto verifyRequestDto = new JWTSignatureVerifyRequestDto();
        verifyRequestDto.setJwtSignatureData("");

        RequestException exception = assertThrows(RequestException.class, () -> {
            signatureService.jwtVerifyV2(verifyRequestDto);
        });

        assertEquals(SignatureErrorCode.INVALID_INPUT.getErrorCode(), exception.getErrorCode());
    }
}