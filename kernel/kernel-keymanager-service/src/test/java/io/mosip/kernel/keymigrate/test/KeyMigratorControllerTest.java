package io.mosip.kernel.keymigrate.test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Collections;
import java.util.List;

import org.junit.Before;
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
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.keymigrate.controller.KeyMigratorController;
import io.mosip.kernel.keymigrate.dto.AuthorizedRolesDTO;
import io.mosip.kernel.keymigrate.dto.KeyMigrateBaseKeyRequestDto;
import io.mosip.kernel.keymigrate.dto.KeyMigrateBaseKeyResponseDto;
import io.mosip.kernel.keymigrate.dto.ZKKeyMigrateCertficateResponseDto;
import io.mosip.kernel.keymigrate.dto.ZKKeyMigrateRequestDto;
import io.mosip.kernel.keymigrate.dto.ZKKeyMigrateResponseDto;
import io.mosip.kernel.keymigrate.dto.ZKKeyResponseDto;
import io.mosip.kernel.keymigrate.service.spi.KeyMigratorService;

@RunWith(SpringRunner.class)
@WebMvcTest(KeyMigratorController.class)
@ContextConfiguration(classes = { KeymanagerTestBootApplication.class, KeyMigratorController.class })
public class KeyMigratorControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private KeyMigratorService keyMigratorService;

    @MockBean(name = "KeymigrateAuthRoles")
    private AuthorizedRolesDTO authorizedRolesDTO;

    private ObjectMapper objectMapper;

    @Before
    public void setUp() {
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule());
        List<String> roles = Collections.singletonList("KEY_MIGRATION_ADMIN");
        when(authorizedRolesDTO.getPostmigratebasekey()).thenReturn(roles);
        when(authorizedRolesDTO.getGetzktempcertificate()).thenReturn(roles);
        when(authorizedRolesDTO.getPostmigratezkkeys()).thenReturn(roles);
    }

    @Test
    @WithMockUser(roles = "KEY_MIGRATION_ADMIN")
    public void testMigrateBaseKey() throws Exception {
        KeyMigrateBaseKeyResponseDto responseDto = new KeyMigrateBaseKeyResponseDto();
        responseDto.setStatus("Success");
        when(keyMigratorService.migrateBaseKey(any())).thenReturn(responseDto);

        RequestWrapper<KeyMigrateBaseKeyRequestDto> requestWrapper = new RequestWrapper<>();
        KeyMigrateBaseKeyRequestDto requestDto = new KeyMigrateBaseKeyRequestDto();
        requestDto.setApplicationId("REGISTRATION");
        requestDto.setReferenceId("REF_123");
        requestDto.setEncryptedKeyData("encrypted-data");
        requestDto.setCertificateData("cert-data");
        requestDto.setNotBefore(java.time.LocalDateTime.now());
        requestDto.setNotAfter(java.time.LocalDateTime.now().plusDays(1));
        requestWrapper.setRequest(requestDto);

        mockMvc.perform(post("/migrateBaseKey")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestWrapper)))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "KEY_MIGRATION_ADMIN")
    public void testGetZKTempCertificate() throws Exception {
        ZKKeyMigrateCertficateResponseDto responseDto = new ZKKeyMigrateCertficateResponseDto();
        responseDto.setCertificate("certificate-data");
        when(keyMigratorService.getZKTempCertificate()).thenReturn(responseDto);

        mockMvc.perform(get("/getZKTempCertificate")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "KEY_MIGRATION_ADMIN")
    public void testMigrateZKKeys() throws Exception {
        ZKKeyMigrateResponseDto responseDto = new ZKKeyMigrateResponseDto();
        ZKKeyResponseDto zkKeyResponseDto = new ZKKeyResponseDto();
        zkKeyResponseDto.setStatusMessage("Success");
        responseDto.setZkEncryptedDataList(Collections.singletonList(zkKeyResponseDto));

        when(keyMigratorService.migrateZKKeys(any())).thenReturn(responseDto);

        RequestWrapper<ZKKeyMigrateRequestDto> requestWrapper = new RequestWrapper<>();
        ZKKeyMigrateRequestDto requestDto = new ZKKeyMigrateRequestDto();
        // Set necessary fields for requestDto if any
        requestWrapper.setRequest(requestDto);

        mockMvc.perform(post("/migrateZKKeys")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestWrapper)))
                .andExpect(status().isOk());
    }
}