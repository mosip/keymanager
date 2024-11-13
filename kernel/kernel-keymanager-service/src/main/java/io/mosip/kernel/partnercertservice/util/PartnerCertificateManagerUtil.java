package io.mosip.kernel.partnercertservice.util;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;

import io.mosip.kernel.core.keymanager.model.CertificateParameters;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.keymanagerservice.entity.CACertificateStore;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.partnercertservice.constant.PartnerCertManagerConstants;
import io.mosip.kernel.partnercertservice.constant.PartnerCertManagerErrorConstants;
import io.mosip.kernel.partnercertservice.exception.PartnerCertManagerException;

/**
 * Utility class for Partner Certificate Management
 * 
 * @author Mahammed Taheer
 * @since 1.1.3
 *
 */
public class PartnerCertificateManagerUtil {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(PartnerCertificateManagerUtil.class);

    private static final int DEFAULT_ALLOWED_CERTIFICATE_DAYS = 315;

    /**
     * Function to check certificate is self-signed.
     * 
     * @param x509Cert X509Certificate
     * 
     * @return true if x509Cert is self-signed, else false
     */
    public static boolean isSelfSignedCertificate(X509Certificate x509Cert) {
        try {
            x509Cert.verify(x509Cert.getPublicKey());
            return true;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException
                | NoSuchProviderException exp) {
            LOGGER.debug(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                    PartnerCertManagerConstants.PCM_UTIL,
                    "Ignore this exception, the exception thrown when signature validation failed.");
        }
        return false;
    }

    public static boolean isMinValidityCertificate(X509Certificate x509Certificate, int minimumValidity) {
        try {
            LocalDateTime timeStamp = DateUtils.getUTCCurrentDateTime().plusMonths(minimumValidity);
            LocalDateTime expiredate = x509Certificate.getNotAfter().toInstant().atZone(ZoneId.of("UTC")).toLocalDateTime();
            return  !expiredate.isBefore(timeStamp);
        } catch (Exception exp) {
            LOGGER.debug(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                    PartnerCertManagerConstants.PCM_UTIL, "Error minimum Validity of Certificate: " + exp.getMessage());
            return false;
        }
    }

    /**
     * Function to format X500Principal of certificate.
     * 
     * @param certPrincipal String form of X500Principal
     * 
     * @return String of Custom format of certificateDN.
     */
    public static String formatCertificateDN(String certPrincipal) {

        X500Name x500Name = new X500Name(certPrincipal);
        StringBuilder strBuilder = new StringBuilder();
        strBuilder.append(getAttributeIfExist(x500Name, BCStyle.CN));
        strBuilder.append(getAttributeIfExist(x500Name, BCStyle.OU));
        strBuilder.append(getAttributeIfExist(x500Name, BCStyle.O));
        strBuilder.append(getAttributeIfExist(x500Name, BCStyle.L));
        strBuilder.append(getAttributeIfExist(x500Name, BCStyle.ST));
        strBuilder.append(getAttributeIfExist(x500Name, BCStyle.C));

        if (strBuilder.length() > 0 && strBuilder.toString().endsWith(",")) {
            return strBuilder.substring(0, strBuilder.length() - 1);
        }
        return strBuilder.toString();
    }

    private static String getAttributeIfExist(X500Name x500Name, ASN1ObjectIdentifier identifier) {
        RDN[] rdns = x500Name.getRDNs(identifier);
        if (rdns.length == 0) {
            return PartnerCertManagerConstants.EMPTY;
        }
        return BCStyle.INSTANCE.oidToDisplayName(identifier) + PartnerCertManagerConstants.EQUALS
                + IETFUtils.valueToString((rdns[0]).getFirst().getValue()) + PartnerCertManagerConstants.COMMA;
    }

    @SuppressWarnings("java:S4790") // added suppress for sonarcloud, sha1 hash is used for certificate identification only not for any sensitive data.
    public static String getCertificateThumbprint(X509Certificate x509Cert) {
        try {
            return DigestUtils.sha1Hex(x509Cert.getEncoded());
        } catch (CertificateEncodingException e) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                    PartnerCertManagerConstants.PCM_UTIL, "Error generating certificate thumbprint.");
            throw new PartnerCertManagerException(PartnerCertManagerErrorConstants.CERTIFICATE_THUMBPRINT_ERROR.getErrorCode(),
                    PartnerCertManagerErrorConstants.CERTIFICATE_THUMBPRINT_ERROR.getErrorMessage());
        }
    }

    public static boolean isCertificateDatesValid(X509Certificate x509Cert) {
        
        try {
            Date currentDate = Date.from(DateUtils.getUTCCurrentDateTime().atZone(ZoneId.systemDefault()).toInstant());
            x509Cert.checkValidity(currentDate);
            return true;
        } catch(CertificateExpiredException | CertificateNotYetValidException exp) {
            LOGGER.debug(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                    PartnerCertManagerConstants.PCM_UTIL,
                    "Ignore this exception, the exception thrown when certificate dates are not valid.");
        }
        try {
            // Checking both system default timezone & UTC Offset timezone. Issue found in reg-client during trust validation. 
            x509Cert.checkValidity();
            return true;
        } catch(CertificateExpiredException | CertificateNotYetValidException exp) {
            LOGGER.debug(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                    PartnerCertManagerConstants.PCM_UTIL,
                    "Ignore this exception, the exception thrown when certificate dates are not valid.");
        }
        return false;
    }

    public static boolean isCertificateValidForDuration(X509Certificate x509Cert, int issuerCertDuration, int gracePeriod) {
        
        int noOfDays = (issuerCertDuration * PartnerCertManagerConstants.YEAR_DAYS) - gracePeriod;
        if (noOfDays < 0) {
            noOfDays = DEFAULT_ALLOWED_CERTIFICATE_DAYS;
        } 
        LocalDateTime localDateTimeStamp = DateUtils.getUTCCurrentDateTime();//.plus(noOfDays, ChronoUnit.DAYS);
        LocalDateTime certNotAfter = x509Cert.getNotAfter().toInstant().atZone(ZoneId.of("UTC")).toLocalDateTime();
        long validDays = ChronoUnit.DAYS.between(localDateTimeStamp, certNotAfter);
        if ((validDays - noOfDays) >= 0)             
            return true;

        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
            PartnerCertManagerConstants.PCM_UTIL, "Remaining validity for the Certificate is " + validDays + 
            " days, grace days configured is " + gracePeriod);
        return false;
    }

    public static boolean isValidTimestamp(LocalDateTime timeStamp, CACertificateStore certStore) {
		boolean valid = timeStamp.isEqual(certStore.getCertNotBefore()) || timeStamp.isEqual(certStore.getCertNotAfter())
				|| (timeStamp.isAfter(certStore.getCertNotBefore())
						&& timeStamp.isBefore(certStore.getCertNotAfter()));
        if (!valid) {
            LocalDateTime localDateTimeNow = LocalDateTime.now();
            valid = localDateTimeNow.isEqual(certStore.getCertNotBefore()) || localDateTimeNow.isEqual(certStore.getCertNotAfter())
				|| (localDateTimeNow.isAfter(certStore.getCertNotBefore())
						&& localDateTimeNow.isBefore(certStore.getCertNotAfter()));
        }
        return valid;
	}

    public static String getCertificateOrgName(X500Principal x500CertPrincipal) {
        X500Name x500Name = new X500Name(x500CertPrincipal.getName());
        RDN[] rdns = x500Name.getRDNs(BCStyle.O);
        if (rdns.length == 0) {
            return PartnerCertManagerConstants.EMPTY;
        }
        return IETFUtils.valueToString((rdns[0]).getFirst().getValue());
    }

    public static boolean isValidCertificateID(String certID) {
		return certID != null && !certID.trim().isEmpty();
    }
    
    public static CertificateParameters getCertificateParameters(X500Principal latestCertPrincipal, LocalDateTime notBefore, 
                                        LocalDateTime notAfter) {

		CertificateParameters certParams = new CertificateParameters();
		X500Name x500Name = new X500Name(latestCertPrincipal.getName());

        certParams.setCommonName(IETFUtils.valueToString((x500Name.getRDNs(BCStyle.CN)[0]).getFirst().getValue()));
        certParams.setOrganizationUnit(getAttributeValueIfExist(x500Name, BCStyle.OU));
        certParams.setOrganization(getAttributeValueIfExist(x500Name, BCStyle.O));
        certParams.setLocation(getAttributeValueIfExist(x500Name, BCStyle.L));
        certParams.setState(getAttributeValueIfExist(x500Name, BCStyle.ST));
        certParams.setCountry(getAttributeValueIfExist(x500Name, BCStyle.C));
		certParams.setNotBefore(notBefore);
		certParams.setNotAfter(notAfter);
        return certParams;
	}

    private static String getAttributeValueIfExist(X500Name x500Name, ASN1ObjectIdentifier identifier) {
        RDN[] rdns = x500Name.getRDNs(identifier);
        if (rdns.length == 0) {
            return PartnerCertManagerConstants.EMPTY;
        }
        return IETFUtils.valueToString((rdns[0]).getFirst().getValue());
    }

    public static String buildP7BCertificateChain(List<? extends Certificate> certList, X509Certificate resignedCert, 
                    String partnerDomain, boolean resignFTMDomainCerts, X509Certificate rootCert, X509Certificate pmsCert) {
        
        if (partnerDomain.toUpperCase().equals(PartnerCertManagerConstants.FTM_PARTNER_DOMAIN) && !resignFTMDomainCerts) {
            return buildCertChain(certList.toArray(new Certificate[0]));
        }
        
        List<Certificate> chain = new ArrayList<>();
        chain.add(resignedCert);
        chain.add(pmsCert);
        chain.add(rootCert);
        return buildCertChain(chain.toArray(new Certificate[0]));
    }

    private static String buildCertChain(Certificate[] chain) {
        
        try {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            JcaCertStore jcaStore = new JcaCertStore(Arrays.asList(chain));
            generator.addCertificates(jcaStore);

            CMSTypedData cmsTypedData = new CMSAbsentContent();
            CMSSignedData cmsSignedData = generator.generate(cmsTypedData);
            return CryptoUtil.encodeToURLSafeBase64(cmsSignedData.getEncoded());
        } catch(CertificateEncodingException | CMSException | IOException e) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                    PartnerCertManagerConstants.PCM_UTIL, "Error generating p7b certificates chain.");
            throw new PartnerCertManagerException(PartnerCertManagerErrorConstants.CERTIFICATE_THUMBPRINT_ERROR.getErrorCode(),
                    PartnerCertManagerErrorConstants.CERTIFICATE_THUMBPRINT_ERROR.getErrorMessage(), e);
        }
    }
    
}