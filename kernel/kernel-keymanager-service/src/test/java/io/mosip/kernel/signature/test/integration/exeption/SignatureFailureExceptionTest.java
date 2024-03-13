package io.mosip.kernel.signature.test.integration.exeption;

import io.mosip.kernel.signature.exception.SignatureFailureException;
import org.junit.Assert;
import org.junit.Test;

public class SignatureFailureExceptionTest {

    @Test
    public void testConstructorWithErrorCodeErrorMessageAndRootCause() {
        String errorCode = "ERR001";
        String errorMessage = "Signature failure";
        Throwable rootCause = new RuntimeException("Root cause");

        SignatureFailureException exception = new SignatureFailureException(errorCode, errorMessage, rootCause);

        Assert.assertEquals(errorCode, exception.getErrorCode());
        Assert.assertEquals(rootCause, exception.getCause());
    }
}
