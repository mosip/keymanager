package io.mosip.kernel.partnercertservice.helper;

import io.mosip.kernel.keymanagerservice.entity.CACertificateStore;
import io.mosip.kernel.keymanagerservice.entity.PartnerCertificateStore;
import io.mosip.kernel.keymanagerservice.repository.CACertificateStoreRepository;
import io.mosip.kernel.keymanagerservice.repository.PartnerCertificateStoreRepository;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.*;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

public class PartnerCertDBHelperTest {

    @Mock
    private CACertificateStoreRepository caCertificateStoreRepository;

    @Mock
    private PartnerCertificateStoreRepository partnerCertificateStoreRepository;

    @Mock
    private KeymanagerUtil keymanagerUtil;

    @InjectMocks
    private PartnerCertManagerDBHelper partnerCertManagerDBHelper;

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testIsCertificateExist_WhenCertificateExists() {
        when(caCertificateStoreRepository.findByCertThumbprintAndPartnerDomain(anyString(), anyString())).thenReturn(new CACertificateStore());
        boolean result = partnerCertManagerDBHelper.isCertificateExist("thumbprint", "partnerDomain");
        Assert.assertTrue(result);
    }

    @Test
    public void testIsCertificateExist_WhenCertificateDoesNotExist() {
        when(caCertificateStoreRepository.findByCertThumbprintAndPartnerDomain(anyString(), anyString())).thenReturn(null);
        boolean result = partnerCertManagerDBHelper.isCertificateExist("thumbprint", "partnerDomain");
        Assert.assertFalse(result);
    }

    @Test
    public void testIsPartnerCertificateExist_WhenCertificateExists() {
        when(partnerCertificateStoreRepository.findByCertThumbprintAndPartnerDomain(anyString(), anyString())).thenReturn(Collections.singletonList(new PartnerCertificateStore()));
        boolean result = partnerCertManagerDBHelper.isPartnerCertificateExist("thumbprint", "partnerDomain");
        Assert.assertTrue(result);
    }

    @Test
    public void testIsPartnerCertificateExist_WhenCertificateDoesNotExist() {
        when(partnerCertificateStoreRepository.findByCertThumbprintAndPartnerDomain(anyString(), anyString())).thenReturn(Collections.emptyList());
        boolean result = partnerCertManagerDBHelper.isPartnerCertificateExist("thumbprint", "partnerDomain");
        Assert.assertFalse(result);
    }

}
