package io.mosip.kernel.cryptomanager.test.exception;

import io.mosip.kernel.cryptomanager.exception.ParseResponseException;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ParseResponseExceptionTest {

    @Test
    public void testConstructorWithErrorCodeAndMessage() {
        String errorCode = "ERR_CRYPTO_001";
        String errorMessage = "Crypto error";
        ParseResponseException exception = new ParseResponseException(errorCode, errorMessage);
        assertEquals(errorCode, exception.getErrorCode());
    }

    @Test
    public void testConstructorWithErrorCodeMessageAndRootCause() {
        String errorCode = "ERR_CRYPTO_001";
        String errorMessage = "Crypto error";
        Throwable rootCause = new RuntimeException("Root cause exception");
        ParseResponseException exception = new ParseResponseException(errorCode, errorMessage,rootCause);
        assertEquals(errorCode, exception.getErrorCode());
    }
}
