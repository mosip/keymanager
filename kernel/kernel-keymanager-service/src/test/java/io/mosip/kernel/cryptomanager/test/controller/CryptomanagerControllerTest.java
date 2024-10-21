
package io.mosip.kernel.cryptomanager.test.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.cryptomanager.dto.*;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.kernel.keymanager.hsm.impl.KeyStoreImpl;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.time.Month;
import java.time.ZoneId;

import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = KeymanagerTestBootApplication.class)
@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
public class CryptomanagerControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private CryptomanagerService service;

    @MockBean
    private KeymanagerService keymanagerService;

    @MockBean
    private KeymanagerDBHelper keymanagerDBHelper;

    @MockBean
    private KeymanagerUtil keymanagerUtil;

    @MockBean
    private KeyStoreImpl keyStore;
    /**
     * TEST SCENARIO :  Testing end points.
     */
    @Test
    @WithUserDetails("reg-processor")
    public void encryptionTest() throws Exception {
        CryptomanagerRequestDto requestDto = new CryptomanagerRequestDto();
        requestDto.setApplicationId("TESTID");
        requestDto.setData("RXhhbXBsZQ==");
        requestDto.setReferenceId("test123");
        requestDto.setTimeStamp(LocalDateTime.of(2024, Month.SEPTEMBER, 23, 17, 38,0));

        CryptomanagerResponseDto responseDto = new CryptomanagerResponseDto();
        responseDto.setData("E2qaKMK8ym00vxjutQb8Sg==");

        given(service.encrypt(Mockito.any())).willReturn(responseDto);
        String json = objectMapper.writeValueAsString(requestDto);
        mockMvc.perform(post("/encrypt").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk());
    }

    @Test
    @WithUserDetails("reg-processor")
    public void decryptionTest() throws Exception {
        CryptomanagerRequestDto requestDto = new CryptomanagerRequestDto();
        requestDto.setApplicationId("TESTID");
        requestDto.setData("E2qaKMK8ym00vxjutQb8Sg==");
        requestDto.setReferenceId("test123");
        requestDto.setTimeStamp(LocalDateTime.now(ZoneId.of("UTC")));

        CryptomanagerResponseDto responseDto = new CryptomanagerResponseDto();
        responseDto.setData("RXhhbXBsZQ==");

        given(service.decrypt(Mockito.any())).willReturn(responseDto);
        String json = objectMapper.writeValueAsString(requestDto);
        mockMvc.perform(post("/decrypt").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk());
    }

    @Test
    @WithUserDetails("reg-processor")
    public void encryptWithPinTest() throws Exception {
        CryptoWithPinRequestDto requestDto = new CryptoWithPinRequestDto();
        requestDto.setData("RXhhbXBsZQ==");
        requestDto.setUserPin("1234");

        CryptoWithPinResponseDto responseDto = new CryptoWithPinResponseDto();
        responseDto.setData("E2qaKMK8ym00vxjutQb8Sg==");

        given(service.encryptWithPin(Mockito.any())).willReturn(responseDto);
        String json = objectMapper.writeValueAsString(requestDto);
        mockMvc.perform(post("/encryptWithPin").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk());
    }

    @Test
    @WithUserDetails("reg-processor")
    public void decryptWithPinTest() throws Exception {
        CryptoWithPinRequestDto requestDto = new CryptoWithPinRequestDto();
        requestDto.setData("E2qaKMK8ym00vxjutQb8Sg==");
        requestDto.setUserPin("1234");

        CryptoWithPinResponseDto responseDto = new CryptoWithPinResponseDto();
        responseDto.setData("RXhhbXBsZQ==");

        given(service.decryptWithPin(Mockito.any())).willReturn(responseDto);
        String json = objectMapper.writeValueAsString(requestDto);
        mockMvc.perform(post("/decryptWithPin").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk());
    }

    @Test
    @WithUserDetails("reg-processor")
    public void jwtEncryptTest() throws Exception {
        JWTEncryptRequestDto requestDto = new JWTEncryptRequestDto();
        requestDto.setApplicationId("TESTID");
        requestDto.setData("dveajdpsnks");
        requestDto.setReferenceId("test123");

        JWTCipherResponseDto responseDto = new JWTCipherResponseDto();
        responseDto.setData("anuhsbisinknskd");
        responseDto.setTimestamp(LocalDateTime.now(ZoneId.of("UTC")));

        given(service.jwtEncrypt(Mockito.any())).willReturn(responseDto);
        String json = objectMapper.writeValueAsString(requestDto);
        mockMvc.perform(post("/jwtEncrypt").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk());
    }

    @Test
    @WithUserDetails("reg-processor")
    public void jwtDecryptTest() throws Exception {
        JWTDecryptRequestDto requestDto = new JWTDecryptRequestDto();
        requestDto.setApplicationId("TESTID");
        requestDto.setEncData("anuhsbisinknskd");
        requestDto.setReferenceId("test123");

        JWTCipherResponseDto responseDto = new JWTCipherResponseDto();
        responseDto.setData("dveajdpsnks");
        responseDto.setTimestamp(LocalDateTime.now(ZoneId.of("UTC")));

        given(service.jwtDecrypt(Mockito.any())).willReturn(responseDto);
        String json = objectMapper.writeValueAsString(requestDto);
        mockMvc.perform(post("/jwtDecrypt").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk());
    }

    @Test
    @WithUserDetails("reg-processor")
    public void generateArgon2HashTest() throws Exception {
        Argon2GenerateHashRequestDto requestDto = new Argon2GenerateHashRequestDto();
        requestDto.setInputData("RXhhbXBsZQ==");

        Argon2GenerateHashResponseDto responseDto = new Argon2GenerateHashResponseDto();
        responseDto.setHashValue("$argon2id$v=19$m=16,t=8,p=2$VXpjRkpieGl5NEtQUjZVaw$/QNX8NYbOPxx5RieIxOXDA");
        responseDto.setSalt("UzcFJbxiy4KPR6Uk");

        given(service.generateArgon2Hash(Mockito.any())).willReturn(responseDto);
        String json = objectMapper.writeValueAsString(requestDto);
        mockMvc.perform(post("/generateArgon2Hash").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk());
    }
}
