package io.mosip.kernel.cryptomanager.test.exception;

import io.mosip.kernel.cryptomanager.exception.CryptoManagerSerivceException;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class CryptoManagerServiceExceptionTest {

    @Test
    public void testConstructorWithErrorCodeAndMessage() {
        String errorCode = "ERR_CRYPTO_001";
        String errorMessage = "Crypto error";
        CryptoManagerSerivceException exception = new CryptoManagerSerivceException(errorCode, errorMessage);
        assertEquals(errorCode, exception.getErrorCode());
    }

    @Test
    public void testConstructorWithErrorCodeMessageAndRootCause() {
        String errorCode = "ERR_CRYPTO_001";
        String errorMessage = "Crypto error";
        Throwable rootCause = new RuntimeException("Root cause exception");
        CryptoManagerSerivceException exception = new CryptoManagerSerivceException(errorCode, errorMessage);
        assertEquals(errorCode, exception.getErrorCode());
    }
}
