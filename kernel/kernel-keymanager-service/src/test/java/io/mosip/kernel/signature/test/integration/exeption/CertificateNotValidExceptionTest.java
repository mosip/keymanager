package io.mosip.kernel.signature.test.integration.exeption;
import io.mosip.kernel.signature.exception.CertificateNotValidException;
import org.junit.Assert;
import org.junit.Test;

public class CertificateNotValidExceptionTest {
    @Test
    public void testConstructorWithErrorCodeAndErrorMessage() {
        String errorCode = "ERR001";
        String errorMessage = "Certificate is not valid";

        CertificateNotValidException exception = new CertificateNotValidException(errorCode, errorMessage);

        Assert.assertEquals(errorCode, exception.getErrorCode());
        Assert.assertNull(exception.getCause());
    }

    @Test
    public void testConstructorWithErrorCodeErrorMessageAndRootCause() {
        String errorCode = "ERR001";
        String errorMessage = "Certificate is not valid";
        Throwable rootCause = new RuntimeException("Root cause");

        CertificateNotValidException exception = new CertificateNotValidException(errorCode, errorMessage, rootCause);

        Assert.assertEquals(errorCode, exception.getErrorCode());
        Assert.assertEquals(rootCause, exception.getCause());
    }
}
