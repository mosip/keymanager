package io.mosip.kernel.signature.test.integration.exeption;
import io.mosip.kernel.signature.exception.RequestException;
import org.junit.Assert;
import org.junit.Test;
public class RequestExceptionTest {

    @Test
    public void testConstructorWithErrorCodeAndErrorMessage() {
        String errorCode = "ERR001";
        String errorMessage = "Invalid request";

        RequestException exception = new RequestException(errorCode, errorMessage);

        Assert.assertEquals(errorCode, exception.getErrorCode());
        Assert.assertNull(exception.getCause());
    }

    @Test
    public void testConstructorWithErrorCodeErrorMessageAndRootCause() {
        String errorCode = "ERR001";
        String errorMessage = "Invalid request";
        Throwable rootCause = new RuntimeException("Root cause");

        RequestException exception = new RequestException(errorCode, errorMessage, rootCause);

        Assert.assertEquals(errorCode, exception.getErrorCode());
        Assert.assertEquals(rootCause, exception.getCause());
    }
}
