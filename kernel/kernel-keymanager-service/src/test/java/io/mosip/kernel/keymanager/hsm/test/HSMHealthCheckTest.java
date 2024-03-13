package io.mosip.kernel.keymanager.hsm.test;

import io.mosip.kernel.core.keymanager.spi.KeyStore;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.keymanager.hsm.health.HSMHealthCheck;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;
import reactor.core.publisher.Mono;

import static org.junit.Assert.assertEquals;

@RunWith(MockitoJUnitRunner.class)
public class HSMHealthCheckTest {
    @Mock
    private KeyStore keyStore;

    @Mock
    private CryptoUtil cryptoUtil;

    @Mock
    private KeymanagerDBHelper dbHelper;

    @InjectMocks
    private HSMHealthCheck hsmHealthCheck;

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testHealthCheckDisabled() throws Exception {
        Mono<Health> healthMono = hsmHealthCheck.health();
        Health health = healthMono.block();
        assertEquals(Status.UP, health.getStatus());
        assertEquals("HEALTH_CHECK_NOT_ENABLED", health.getDetails().get("Info: "));
    }

}
