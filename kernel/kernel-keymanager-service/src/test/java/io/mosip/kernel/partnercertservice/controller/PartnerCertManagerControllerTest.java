package io.mosip.kernel.partnercertservice.controller;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import io.mosip.kernel.partnercertservice.dto.CACertificateRequestDto;
import io.mosip.kernel.partnercertservice.dto.PartnerCertDownloadRequestDto;
import io.mosip.kernel.partnercertservice.dto.PartnerCertDownloadResponeDto;
import io.mosip.kernel.partnercertservice.service.spi.PartnerCertificateManagerService;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseWrapper;

import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.access.AccessDeniedException;

public class PartnerCertManagerControllerTest {

    @Mock
    private PartnerCertificateManagerService partnerCertManagerService;

    @InjectMocks
    private PartnerCertManagerController partnerCertManagerController;

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testGetPartnerCertificate() {
        String partnerCertId = "12345";
        PartnerCertDownloadRequestDto requestDto = new PartnerCertDownloadRequestDto();
        requestDto.setPartnerCertId(partnerCertId);
        PartnerCertDownloadResponeDto responseDto = new PartnerCertDownloadResponeDto();
        ResponseWrapper<PartnerCertDownloadResponeDto> expectedResponse = new ResponseWrapper<>();
        expectedResponse.setResponse(responseDto);
        when(partnerCertManagerService.getPartnerCertificate(any())).thenReturn(responseDto);
        ResponseWrapper<PartnerCertDownloadResponeDto> actualResponse = partnerCertManagerController.getPartnerCertificate(partnerCertId);
        expectedResponse.setResponsetime(actualResponse.getResponsetime());

        assertEquals(expectedResponse, actualResponse);
    }

    @Test(expected = AccessDeniedException.class)
    public void testAccessDeniedException() {

        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        RequestWrapper<CACertificateRequestDto> requestWrapper = new RequestWrapper<>();
        when(partnerCertManagerService.uploadCACertificate(any())).thenThrow(AccessDeniedException.class);
        partnerCertManagerController.uploadCACertificate(requestWrapper);
    }
}
