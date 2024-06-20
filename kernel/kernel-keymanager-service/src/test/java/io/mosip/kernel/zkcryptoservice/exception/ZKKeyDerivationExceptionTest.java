package io.mosip.kernel.zkcryptoservice.exception;

import org.junit.Assert;
import org.junit.Test;

public class ZKKeyDerivationExceptionTest {

    @Test
    public void testConstructorWithErrorMessage() {
        String errorCode = "ERROR_CODE";
        String errorMessage = "Error message";

        ZKKeyDerivationException exception = new ZKKeyDerivationException(errorCode, errorMessage);

        Assert.assertEquals(errorCode, exception.getErrorCode());
    }

    @Test
    public void testConstructorWithErrorMessageAndRootCause() {
        String errorCode = "ERROR_CODE";
        String errorMessage = "Error message";
        Throwable rootCause = new RuntimeException("Root cause");

        ZKKeyDerivationException exception = new ZKKeyDerivationException(errorCode, errorMessage, rootCause);

        Assert.assertEquals(errorCode, exception.getErrorCode());
    }

}
