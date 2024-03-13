package io.mosip.kernel.lkeymanager.test.util;
import io.mosip.kernel.lkeymanager.exception.InvalidArgumentsException;
import io.mosip.kernel.lkeymanager.util.LicenseKeyManagerUtil;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.List;

@RunWith(MockitoJUnitRunner.class)
public class LicenseKeyManagerUtilTest {
    @InjectMocks
    private LicenseKeyManagerUtil licenseKeyManagerUtil;

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testConcatPermissionsIntoASingleRow() {
        List<String> permissionsList = Arrays.asList("permission1", "permission2", "permission3");
        String expected = "permission1,permission2,permission3";

        String result = licenseKeyManagerUtil.concatPermissionsIntoASingleRow(permissionsList);

        Assert.assertEquals(expected, result);
    }

    @Test
    public void testValidateTSP_ValidTSP() {
        String tspID = "TSP123";
        licenseKeyManagerUtil.validateTSP(tspID);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void testValidateTSP_InvalidTSP() {
        String tspID = null;
        licenseKeyManagerUtil.validateTSP(tspID);
    }

    @Test
    public void testValidateTSPAndLicenseKey_ValidTSPAndLicenseKey() {
        String tspID = "TSP123";
        String licenseKey = "ABC123xyz";
        licenseKeyManagerUtil.validateTSPAndLicenseKey(tspID, licenseKey);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void testValidateTSPAndLicenseKey_InvalidTSP() {
        String tspID = null;
        String licenseKey = "ABC123xyz";
        licenseKeyManagerUtil.validateTSPAndLicenseKey(tspID, licenseKey);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void testValidateTSPAndLicenseKey_InvalidLicenseKey() {
        String tspID = "TSP123";
        String licenseKey = null;

        licenseKeyManagerUtil.validateTSPAndLicenseKey(tspID, licenseKey);
    }

    @Test
    public void testValidateRequestParameters_ValidParameters() {
        String tspID = "TSP123";
        String licenseKey = "ABC123xyz";
        List<String> permissions= Arrays.asList("permission1", "permission2");

        licenseKeyManagerUtil.validateRequestParameters(tspID, licenseKey, permissions);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void testValidateRequestParameters_InvalidTSP() {
        String tspID = null;
        String licenseKey = "ABC123xyz";
        List<String> permissions = Arrays.asList("permission1", "permission2");

        licenseKeyManagerUtil.validateRequestParameters(tspID, licenseKey, permissions);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void testValidateRequestParameters_InvalidLicenseKey() {
        String tspID = "TSP123";
        String licenseKey = null;
        List<String> permissions = Arrays.asList("permission1", "permission2");
        licenseKeyManagerUtil.validateRequestParameters(tspID, licenseKey, permissions);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void testValidateRequestParameters_InvalidPermission() {
        String tspID = "TSP123";
        String licenseKey = "ABC123xyz";
        List<String> permissions = Arrays.asList("permission1", "");
        licenseKeyManagerUtil.validateRequestParameters(tspID, licenseKey, permissions);
    }
}
