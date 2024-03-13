package io.mosip.kernel.partnercertservice.exception;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class PartnerCertManagerExceptionTest {

    @Test
    public void testConstructorWithErrorCodeAndErrorMessage() {
        PartnerCertManagerException exception = new PartnerCertManagerException("ERROR_CODE", "Error message");
        assertEquals("ERROR_CODE", exception.getErrorCode());
    }

    @Test
    public void testConstructorWithErrorCodeErrorMessageAndRootCause() {
        Exception rootCause = new Exception("Root cause");
        PartnerCertManagerException exception = new PartnerCertManagerException("ERROR_CODE", "Error message", rootCause);
        assertEquals("ERROR_CODE", exception.getErrorCode());
    }
}
