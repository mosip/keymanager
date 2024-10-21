
package io.mosip.kernel.cryptomanager.test.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.cryptomanager.util.KeymanagerSymmetricKeyConverter;
import io.mosip.kernel.keymanager.hsm.impl.KeyStoreImpl;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.kernel.cryptomanager.dto.KeymanagerSymmetricKeyRequestDto;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.time.ZoneId;

@SpringBootTest(classes = KeymanagerTestBootApplication.class)
@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
public class KeymanagerSymmetricKeyConverterTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @MockBean
    KeyStoreImpl keyStore;

    private KeymanagerSymmetricKeyConverter converter;
    private CryptomanagerRequestDto cryptomanagerRequestDto;
    private KeymanagerSymmetricKeyRequestDto keymanagerSymmetricKeyRequestDto;

    @Before
    public void setUp() {
        converter = new KeymanagerSymmetricKeyConverter();
        cryptomanagerRequestDto = mock(CryptomanagerRequestDto.class);
        keymanagerSymmetricKeyRequestDto = new KeymanagerSymmetricKeyRequestDto();
    }

    /**
     * TEST SCENARIO : Testing Convert method
     *
     * {@link KeymanagerSymmetricKeyConverter#convert(CryptomanagerRequestDto, KeymanagerSymmetricKeyRequestDto)}
     */
    @Test
    public void testConvert() {
        cryptomanagerRequestDto = new CryptomanagerRequestDto();
        cryptomanagerRequestDto.setApplicationId("app123");
        cryptomanagerRequestDto.setReferenceId("ref456");
        cryptomanagerRequestDto.setTimeStamp(LocalDateTime.now(ZoneId.of("UTC")));
        cryptomanagerRequestDto.setData("encryptedKeySample");

        converter.convert(cryptomanagerRequestDto, keymanagerSymmetricKeyRequestDto);

        assertEquals(cryptomanagerRequestDto.getApplicationId(), keymanagerSymmetricKeyRequestDto.getApplicationId());
        assertEquals(cryptomanagerRequestDto.getReferenceId(), keymanagerSymmetricKeyRequestDto.getReferenceId());
        assertEquals(cryptomanagerRequestDto.getTimeStamp(), keymanagerSymmetricKeyRequestDto.getTimeStamp());
        assertEquals(cryptomanagerRequestDto.getData(), keymanagerSymmetricKeyRequestDto.getEncryptedSymmetricKey());
    }
}
