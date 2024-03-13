package io.mosip.kernel.clientcrypto.test.exception;

import io.mosip.kernel.clientcrypto.exception.ClientCryptoException;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ClientCryptoExceptionTest {

    @Test
    public void testConstructorWithErrorCodeAndMessage() {
        String errorCode = "ERR_CRYPTO_001";
        String errorMessage = "Crypto error";

        ClientCryptoException exception = new ClientCryptoException(errorCode, errorMessage);

        assertEquals(errorCode, exception.getErrorCode());
    }

    @Test
    public void testConstructorWithErrorCodeMessageAndRootCause() {
        String errorCode = "ERR_CRYPTO_001";
        String errorMessage = "Crypto error";
        Throwable rootCause = new RuntimeException("Root cause exception");

        ClientCryptoException exception = new ClientCryptoException(errorCode, errorMessage, rootCause);

        assertEquals(errorCode, exception.getErrorCode());
    }
}
