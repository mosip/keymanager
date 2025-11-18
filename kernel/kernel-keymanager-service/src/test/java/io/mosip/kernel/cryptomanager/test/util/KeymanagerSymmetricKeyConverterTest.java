package io.mosip.kernel.cryptomanager.test.util;

import static org.junit.Assert.*;

import java.time.LocalDateTime;

import org.junit.Before;
import org.junit.Test;

import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.kernel.cryptomanager.dto.KeymanagerSymmetricKeyRequestDto;
import io.mosip.kernel.cryptomanager.util.KeymanagerSymmetricKeyConverter;

public class KeymanagerSymmetricKeyConverterTest {

    private KeymanagerSymmetricKeyConverter converter;
    private CryptomanagerRequestDto source;
    private KeymanagerSymmetricKeyRequestDto destination;

    @Before
    public void setUp() {
        converter = new KeymanagerSymmetricKeyConverter();
        
        source = new CryptomanagerRequestDto();
        source.setApplicationId("TEST_APP");
        source.setReferenceId("REF_001");
        source.setTimeStamp(LocalDateTime.of(2023, 11, 18, 10, 30, 0));
        source.setData("encryptedSymmetricKeyData");
        
        destination = new KeymanagerSymmetricKeyRequestDto();
    }

    @Test
    public void testConvert_Success() {
        converter.convert(source, destination);
        
        assertEquals("TEST_APP", destination.getApplicationId());
        assertEquals("REF_001", destination.getReferenceId());
        assertEquals(LocalDateTime.of(2023, 11, 18, 10, 30, 0), destination.getTimeStamp());
        assertEquals("encryptedSymmetricKeyData", destination.getEncryptedSymmetricKey());
    }

    @Test
    public void testConvert_WithNullValues() {
        CryptomanagerRequestDto nullSource = new CryptomanagerRequestDto();
        nullSource.setApplicationId(null);
        nullSource.setReferenceId(null);
        nullSource.setTimeStamp(null);
        nullSource.setData(null);
        
        converter.convert(nullSource, destination);
        
        assertNull(destination.getApplicationId());
        assertNull(destination.getReferenceId());
        assertNull(destination.getTimeStamp());
        assertNull(destination.getEncryptedSymmetricKey());
    }

    @Test
    public void testConvert_WithEmptyStrings() {
        CryptomanagerRequestDto emptySource = new CryptomanagerRequestDto();
        emptySource.setApplicationId("");
        emptySource.setReferenceId("");
        emptySource.setData("");
        emptySource.setTimeStamp(LocalDateTime.now());
        
        converter.convert(emptySource, destination);
        
        assertEquals("", destination.getApplicationId());
        assertEquals("", destination.getReferenceId());
        assertEquals("", destination.getEncryptedSymmetricKey());
        assertNotNull(destination.getTimeStamp());
    }

    @Test
    public void testConvert_PreservesExistingDestinationValues() {
        destination.setApplicationId("OLD_APP");
        destination.setReferenceId("OLD_REF");
        
        converter.convert(source, destination);
        
        assertEquals("TEST_APP", destination.getApplicationId());
        assertEquals("REF_001", destination.getReferenceId());
    }

    @Test
    public void testConvert_WithSpecialCharacters() {
        source.setApplicationId("APP@123");
        source.setReferenceId("REF#456");
        source.setData("data$with%special&chars");
        
        converter.convert(source, destination);
        
        assertEquals("APP@123", destination.getApplicationId());
        assertEquals("REF#456", destination.getReferenceId());
        assertEquals("data$with%special&chars", destination.getEncryptedSymmetricKey());
    }
}