package io.mosip.kernel.clientcrypto.test.service;

import io.mosip.kernel.clientcrypto.constant.ClientType;
import io.mosip.kernel.clientcrypto.dto.*;
import io.mosip.kernel.clientcrypto.service.impl.ClientCryptoManagerServiceImpl;
import io.mosip.kernel.clientcrypto.test.ClientCryptoTestBootApplication;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.*;

@SpringBootTest(classes = { ClientCryptoTestBootApplication.class })
@RunWith(SpringRunner.class)
public class ClientCryptoManagerServiceImplTest {

    @Autowired
    private ClientCryptoManagerServiceImpl service;

    String publicKey = "MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBYSDpSME6aWatl7G6nzYIK" +
            "FJb2IoFKpPLub8EpS8ZbwZq5PULzDwEO9z6OAJgdHHHSZCDVfQV6j+7kpuRf9hpq" +
            "YANA0a3+kMrHzlOAcYB4jSl6HOmDw9ze7rKD9m8pOoyjGN1/+vlSbs26q/pjWaem" +
            "4TzEoLX+8mI+kw65Vnwo8MTeJuzFrbuqvCkMLG8OLwVdZMs3/4+F0R7fPrz481wJ" +
            "bEH35X28Decf0PWp5jpRH7OJc9sAsazK1jKb4802TKgzS+KUX4mkNBiHDz21mM1Q" +
            "E61N5F66sOOi8wQYIlmBXpLzyfIkSh4wiG8jia+bGWEVZkc5FqJPJff6OSctkpZX" +
            "AgMBAAE=";

    @Test
    public void csSignTest() {
        TpmSignRequestDto requestDto = new TpmSignRequestDto();
        requestDto.setData("RGF0YSB0byBTaWdu");

        String signedData = "nviZKvRaBWV0BpNhgxNHkp6uGP2vLn2sXRjW11EUPapH1cYv2csj1htMVXkdCoSjfVAZeO9DmAcdIehIB1KGSKevEoNsgr-xeZmfBXk_gLZxo0BOvwAFUudGLbCmeG-F7uDktMWA3V7QMsbKamMe8zlI-eP7bg5q37ecYpIZZ2XB0A24rz9vXQlZgi2io8GSUCi6nkOYNPGJYZEZs5waTpWO-YScQY2vi521DNoFfIcyQ2wEjPmeJRVym59j3FLe-REGUjkhPnrt8PmnsqzpFxtkbgCLusu1KJ6Vpcdb27OZTrBz4A_ZeMT2cOE59TUP9imZwGElWHwniXzClOj6Hg";
        TpmSignResponseDto responseDto = new TpmSignResponseDto();
        responseDto.setData(signedData);

        TpmSignResponseDto result = service.csSign(requestDto);
        assertEquals(responseDto, result);
    }

    @Test
    public void csVerifyTest() {
        String signature = "nviZKvRaBWV0BpNhgxNHkp6uGP2vLn2sXRjW11EUPapH1cYv2csj1htMVXkdCoSjfVAZeO9DmAcdIehIB1KGSKevEoNsgr-xeZmfBXk_gLZxo0BOvwAFUudGLbCmeG-F7uDktMWA3V7QMsbKamMe8zlI-eP7bg5q37ecYpIZZ2XB0A24rz9vXQlZgi2io8GSUCi6nkOYNPGJYZEZs5waTpWO-YScQY2vi521DNoFfIcyQ2wEjPmeJRVym59j3FLe-REGUjkhPnrt8PmnsqzpFxtkbgCLusu1KJ6Vpcdb27OZTrBz4A_ZeMT2cOE59TUP9imZwGElWHwniXzClOj6Hg";
        TpmSignVerifyRequestDto requestDto = new TpmSignVerifyRequestDto();
        requestDto.setData("RGF0YSB0byBTaWdu");
        requestDto.setSignature(signature);
        requestDto.setPublicKey(publicKey);

        TpmSignVerifyResponseDto responseDto = new TpmSignVerifyResponseDto();
        responseDto.setVerified(false);

        TpmSignVerifyResponseDto result = service.csVerify(requestDto);
        assertEquals(responseDto, result);

        requestDto.setClientType(ClientType.ANDROID);
        assertEquals(responseDto, service.csVerify(requestDto));

        requestDto.setClientType(ClientType.LOCAL);
        assertEquals(responseDto, service.csVerify(requestDto));
    }

    @Test
    public void csEncryptTest() {
        TpmCryptoRequestDto requestDto = new TpmCryptoRequestDto();
        requestDto.setValue("U2FtcGxlIFRlc3QgRGF0YQ==");
        requestDto.setPublicKey(publicKey);

        TpmCryptoResponseDto result = service.csEncrypt(requestDto);
        assertNotNull(result);

        requestDto.setClientType(ClientType.ANDROID);
        assertNotNull(service.csEncrypt(requestDto));
    }

    @Test
    public void getSigningPublicKeyTest() {
        PublicKeyRequestDto requestDto = new PublicKeyRequestDto();
        requestDto.setServerProfile("Dev0");

        String pbKey = "AAEABAAEAHIAAAAQABQACwgAAAEAAQEAwIkFw_gLJ2NoIVuEwWeY0UxnS-5G6Su5YqvOWTJQt-dyZpgu02kErg_6Ntk4kMnXyQCZN6Eh4wxoAdLkrg4MknERmKfvOCsVvLZATYSHk4ju1wEy_8bFWaV98Umpaq0cLWE7g3fyWd-IRT7kLTcMWS-WBLzwhUN2greg5snLoXtGdsIrN7cwlefA94O6gZ_OPAMuJeiwvxTQM88mYcAbEIXQ6fPYgsL1yQcjSnvELisppj0_kbbhd4xpgAN3gqudHUFLR0TIBEjCNHEEyuPoc5CN6arzFjPJkIT1HPcpjlZyZCEGXPBzbhl7PrFq5h0q-r1eTBELaNt-50qkcOYlAQ";
        PublicKeyResponseDto responseDto = new PublicKeyResponseDto();
        responseDto.setPublicKey(pbKey);

        PublicKeyResponseDto result = service.getSigningPublicKey(requestDto);
        assertEquals(responseDto, result);
    }

    @Test
    public void getEncPublicKeyTest() {
        PublicKeyRequestDto requestDto = new PublicKeyRequestDto();
        requestDto.setServerProfile("Dev0");

        String encPbKey = "AAEACwACAHIAIINxl2dEhLP4GpDMjUal1yT9UtduBlILZPKh2hszFGmqABAAFwALCAAAAQABAQC_2h69Q6XENceqzzotPZep7fHLgelDIMeszyPKuVgB5BSfmGJ4fdsaoBtVKCjpJ-jwSKzy7oKgUCNJO-Dtyb8AQ9e8yAEkzdh1PAsKpsrbLogl2G2O-5Rb7UjB6A0wmb2YBh20K3-3Gj2Uh5nbrTso-u_1aILZA-CXqg12LosMBwvPq3vbFmkS--96R3Sc94nxyMgAi4DENaPm2CLIIMwxdmxtLIjRcWlHNbg7uZzi0fVNwiilZbnVIWYvi7pOTekXWz17lVb8InEQEZTZx5yT_RvqEMHyvMFt6zKnM_yYfuQ0n-kUZ3Of3DCvC2UDAC2r7m-48fD9PVjY7_7Wrh_D";
        PublicKeyResponseDto responseDto = new PublicKeyResponseDto();
        responseDto.setPublicKey(encPbKey);

        PublicKeyResponseDto result = service.getEncPublicKey(requestDto);
        assertEquals(responseDto, result);

    }
}
