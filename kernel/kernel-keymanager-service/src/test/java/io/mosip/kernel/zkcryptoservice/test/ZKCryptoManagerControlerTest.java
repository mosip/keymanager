package io.mosip.kernel.zkcryptoservice.test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.zkcryptoservice.controller.ZKCryptoManagerController;
import io.mosip.kernel.zkcryptoservice.dto.AuthorizedRolesDTO;
import io.mosip.kernel.zkcryptoservice.dto.CryptoDataDto;
import io.mosip.kernel.zkcryptoservice.dto.ReEncryptRandomKeyResponseDto;
import io.mosip.kernel.zkcryptoservice.dto.ZKCryptoRequestDto;
import io.mosip.kernel.zkcryptoservice.dto.ZKCryptoResponseDto;
import io.mosip.kernel.zkcryptoservice.service.spi.ZKCryptoManagerService;

@RunWith(SpringRunner.class)
@WebMvcTest(ZKCryptoManagerController.class)
@ContextConfiguration(classes = ZKCryptoManagerControlerTest.TestConfig.class)
public class ZKCryptoManagerControlerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ZKCryptoManagerService zkCryptoManagerService;

    @MockBean(name = "zkAuthRoles")
    private AuthorizedRolesDTO authorizedRolesDTO;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @WithMockUser(roles = "ZONAL_ADMIN")
    public void testZkEncryptSuccess() throws Exception {
        ZKCryptoRequestDto requestDto = new ZKCryptoRequestDto();
        requestDto.setId("12345");
        CryptoDataDto cryptoData = new CryptoDataDto();
        cryptoData.setIdentifier("name");
        cryptoData.setValue("John Doe");
        List<CryptoDataDto> list = new ArrayList<>();
        list.add(cryptoData);
        requestDto.setZkDataAttributes(list);

        RequestWrapper<ZKCryptoRequestDto> requestWrapper = new RequestWrapper<>();
        requestWrapper.setRequest(requestDto);

        ZKCryptoResponseDto responseDto = new ZKCryptoResponseDto();
        responseDto.setZkDataAttributes(list);
        responseDto.setEncryptedRandomKey("encryptedKey");
        responseDto.setRankomKeyIndex("1");

        when(authorizedRolesDTO.getPostzkencrypt()).thenReturn(List.of("ZONAL_ADMIN"));
        when(zkCryptoManagerService.zkEncrypt(any(ZKCryptoRequestDto.class))).thenReturn(responseDto);

        mockMvc.perform(post("/zkEncrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestWrapper))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.zkDataAttributes[0].identifier").value("name"))
                .andExpect(jsonPath("$.response.zkDataAttributes[0].value").value("John Doe"))
                .andExpect(jsonPath("$.response.encryptedRandomKey").value("encryptedKey"))
                .andExpect(jsonPath("$.response.rankomKeyIndex").value("1"));
    }

    @Test
    @WithMockUser(roles = "ZONAL_ADMIN")
    public void testZkDecryptSuccess() throws Exception {
        ZKCryptoRequestDto requestDto = new ZKCryptoRequestDto();
        requestDto.setId("12345");
        CryptoDataDto cryptoData = new CryptoDataDto();
        cryptoData.setIdentifier("name");
        cryptoData.setValue("EncryptedValue");
        List<CryptoDataDto> list = new ArrayList<>();
        list.add(cryptoData);
        requestDto.setZkDataAttributes(list);

        RequestWrapper<ZKCryptoRequestDto> requestWrapper = new RequestWrapper<>();
        requestWrapper.setRequest(requestDto);

        ZKCryptoResponseDto responseDto = new ZKCryptoResponseDto();
        CryptoDataDto decryptedData = new CryptoDataDto();
        decryptedData.setIdentifier("name");
        decryptedData.setValue("DecryptedValue");
        List<CryptoDataDto> decryptedList = new ArrayList<>();
        decryptedList.add(decryptedData);
        responseDto.setZkDataAttributes(decryptedList);

        when(authorizedRolesDTO.getPostzkdecrypt()).thenReturn(List.of("ZONAL_ADMIN"));
        when(zkCryptoManagerService.zkDecrypt(any(ZKCryptoRequestDto.class))).thenReturn(responseDto);

        mockMvc.perform(post("/zkDecrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestWrapper))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.zkDataAttributes[0].identifier").value("name"))
                .andExpect(jsonPath("$.response.zkDataAttributes[0].value").value("DecryptedValue"));
    }

    @Test
    @WithMockUser(roles = "ZONAL_ADMIN")
    public void testZkReEncryptRandomKeySuccess() throws Exception {
        String encryptedKey = "encryptedKey";
        ReEncryptRandomKeyResponseDto responseDto = new ReEncryptRandomKeyResponseDto();
        responseDto.setEncryptedKey("reEncryptedKey");

        when(authorizedRolesDTO.getPostzkreencryptrandomkey()).thenReturn(List.of("ZONAL_ADMIN"));
        when(zkCryptoManagerService.zkReEncryptRandomKey(any(String.class))).thenReturn(responseDto);

        mockMvc.perform(post("/zkReEncryptRandomKey")
                        .param("encryptedKey", encryptedKey)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.encryptedKey").value("reEncryptedKey"));
    }

    @Test
    @WithMockUser(roles = "ZONAL_ADMIN")
    public void testZkEncryptValidationFailure() throws Exception {
        ZKCryptoRequestDto requestDto = new ZKCryptoRequestDto();
        // Missing required fields to trigger validation error

        RequestWrapper<ZKCryptoRequestDto> requestWrapper = new RequestWrapper<>();
        requestWrapper.setRequest(requestDto);

        when(authorizedRolesDTO.getPostzkencrypt()).thenReturn(List.of("ZONAL_ADMIN"));

        mockMvc.perform(post("/zkEncrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestWrapper))
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }

    @org.springframework.boot.autoconfigure.SpringBootApplication
    @org.springframework.context.annotation.ComponentScan(basePackages = "io.mosip.kernel.zkcryptoservice.controller")
    static class TestConfig {
    }
}