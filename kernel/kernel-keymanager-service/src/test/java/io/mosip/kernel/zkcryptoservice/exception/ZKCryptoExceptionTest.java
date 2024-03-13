package io.mosip.kernel.zkcryptoservice.exception;

import org.junit.Assert;
import org.junit.Test;

public class ZKCryptoExceptionTest {
    @Test
    public void testConstructorWithErrorMessage() {
        String errorCode = "ERROR_CODE";
        String errorMessage = "Error message";

        ZKCryptoException exception = new ZKCryptoException(errorCode, errorMessage);

        Assert.assertEquals(errorCode, exception.getErrorCode());
    }

    @Test
    public void testConstructorWithErrorMessageAndRootCause() {
        String errorCode = "ERROR_CODE";
        String errorMessage = "Error message";
        Throwable rootCause = new RuntimeException("Root cause");

        ZKCryptoException exception = new ZKCryptoException(errorCode, errorMessage, rootCause);

        Assert.assertEquals(errorCode, exception.getErrorCode());
    }
}
