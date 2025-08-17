package io.mosip.kernel.keymigrate.service.test;
import io.mosip.kernel.keymigrate.dto.KeyMigrateBaseKeyRequestDto;
import io.mosip.kernel.keymigrate.dto.KeyMigrateBaseKeyResponseDto;
import io.mosip.kernel.keymigrate.dto.ZKKeyMigrateCertficateResponseDto;
import io.mosip.kernel.keymigrate.dto.ZKKeyMigrateRequestDto;
import io.mosip.kernel.keymigrate.dto.ZKKeyMigrateResponseDto;
import io.mosip.kernel.keymigrate.service.spi.KeyMigratorService;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import static org.mockito.Mockito.when;

public class KeyMigratorServiceTest {

    @Mock
    private KeyMigratorService keyMigratorService;

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testMigrateBaseKey() {
        KeyMigrateBaseKeyRequestDto requestDto = new KeyMigrateBaseKeyRequestDto();
        KeyMigrateBaseKeyResponseDto expectedResponse = new KeyMigrateBaseKeyResponseDto();
        when(keyMigratorService.migrateBaseKey(requestDto)).thenReturn(expectedResponse);
        KeyMigrateBaseKeyResponseDto actualResponse = keyMigratorService.migrateBaseKey(requestDto);
        Assert.assertEquals(expectedResponse, actualResponse);
    }

    @Test
    public void testGetZKTempCertificate() {
        ZKKeyMigrateCertficateResponseDto expectedResponse = new ZKKeyMigrateCertficateResponseDto();
        when(keyMigratorService.getZKTempCertificate()).thenReturn(expectedResponse);
        ZKKeyMigrateCertficateResponseDto actualResponse = keyMigratorService.getZKTempCertificate();
        Assert.assertEquals(expectedResponse, actualResponse);
    }

    @Test
    public void testMigrateZKKeys() {
        ZKKeyMigrateRequestDto requestDto = new ZKKeyMigrateRequestDto();
        ZKKeyMigrateResponseDto expectedResponse = new ZKKeyMigrateResponseDto();
        when(keyMigratorService.migrateZKKeys(requestDto)).thenReturn(expectedResponse);
        ZKKeyMigrateResponseDto actualResponse = keyMigratorService.migrateZKKeys(requestDto);
        Assert.assertEquals(expectedResponse, actualResponse);
    }
}
