package io.mosip.kernel.signature.test.integration.exeption;

import io.mosip.kernel.signature.exception.PublicKeyParseException;
import org.junit.Assert;
import org.junit.Test;

public class PublicKeyParseExceptionTest {

    @Test
    public void testConstructorWithErrorCodeErrorMessageAndRootCause() {
        String errorCode = "ERR001";
        String errorMessage = "Error parsing public key";
        Throwable rootCause = new RuntimeException("Root cause");

        PublicKeyParseException exception = new PublicKeyParseException(errorCode, errorMessage, rootCause);

        Assert.assertEquals(errorCode, exception.getErrorCode());
        Assert.assertEquals(rootCause, exception.getCause());
    }
}
