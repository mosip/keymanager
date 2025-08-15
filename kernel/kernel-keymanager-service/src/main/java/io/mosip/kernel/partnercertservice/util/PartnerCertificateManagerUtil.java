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
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.*;

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
            LocalDate timeStamp = DateUtils.getUTCCurrentDateTime().plusMonths(minimumValidity).toLocalDate();
            LocalDate expiredate = x509Certificate.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
            return !expiredate.isBefore(timeStamp);
        } catch (Exception exp) {
            LOGGER.debug(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                    PartnerCertManagerConstants.PCM_UTIL, "Error minimum Validity of Certificate: " + exp.getMessage());
            return false;
        }
    }

    public static boolean isFutureDatedCertificate(X509Certificate x509Certificate) {
        try {
            LocalDate timeStamp = DateUtils.getUTCCurrentDateTime().toLocalDate();
            LocalDate createdDate = x509Certificate.getNotBefore().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
            return !createdDate.isAfter(timeStamp);
        } catch (Exception exp) {
            LOGGER.debug(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                    PartnerCertManagerConstants.PCM_UTIL, "Future Dated Certificated Not allowed to upload.");
        }
        return false;
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

    public static String buildp7bFile(Certificate[] chain) {
        return buildCertChainWithPKCS7(chain);
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

    public static String buildCertChainWithPKCS7(Certificate[] chain) {
        try {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            JcaCertStore jcaStore = new JcaCertStore(Arrays.asList(chain));
            generator.addCertificates(jcaStore);

            CMSTypedData cmsTypedData = new CMSAbsentContent();
            CMSSignedData cmsSignedData = generator.generate(cmsTypedData);

            byte[] encodedData = cmsSignedData.getEncoded();
            String base64Encoded = Base64.getEncoder().encodeToString(encodedData);

            StringBuilder pkcs7Formatted = new StringBuilder();
            pkcs7Formatted.append("-----BEGIN PKCS7-----\n");
            pkcs7Formatted.append(base64Encoded.replaceAll("(.{64})", "$1\n"));
            pkcs7Formatted.append("\n-----END PKCS7-----");

            return pkcs7Formatted.toString();
        } catch (CertificateEncodingException | CMSException | IOException e) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.GET_CA_CERT_TRUST,
                    PartnerCertManagerConstants.PCM_UTIL, "Error generating p7b certificates chain.");
            throw new PartnerCertManagerException(
                    PartnerCertManagerErrorConstants.P7B_CONVERSION_ERROR.getErrorCode(),
                    PartnerCertManagerErrorConstants.P7B_CONVERSION_ERROR.getErrorMessage(), e);
        }
    }

    public static String handleNullOrEmpty(String value) {
        return (value == null || value.trim().isEmpty()) ? null : value;
    }

    // ---- Minimal DER reader (no external deps) ----
    private static final int TAG_OCTET_STRING = 0x04;
    private static final int TAG_SEQUENCE     = 0x30;
    private static final int TAG_CTX0_PRIM    = 0x80; // [0] primitive
    private static final int TAG_CTX0_CONS    = 0xA0; // [0] constructed

    private static final class DerReader {
        private final byte[] buf;
        private int pos;

        DerReader(byte[] buf) { this.buf = buf; this.pos = 0; }

        boolean hasRemaining() { return pos < buf.length; }

        // Returns tag (unsigned byte 0..255)
        int readTag() {
            if (pos >= buf.length) throw new IllegalArgumentException("Truncated DER: tag");
            return buf[pos++] & 0xFF;
        }

        int readLength() {
            if (pos >= buf.length) throw new IllegalArgumentException("Truncated DER: length");
            int b = buf[pos++] & 0xFF;
            if ((b & 0x80) == 0) return b;                // short form
            int num = b & 0x7F;                           // long form
            if (num == 0 || num > 4) throw new IllegalArgumentException("Invalid DER length");
            if (pos + num > buf.length) throw new IllegalArgumentException("Truncated DER: length bytes");
            int len = 0;
            for (int i = 0; i < num; i++) {
                len = (len << 8) | (buf[pos++] & 0xFF);
            }
            return len;
        }

        byte[] readBytes(int len) {
            if (pos + len > buf.length) throw new IllegalArgumentException("Truncated DER: value");
            byte[] out = java.util.Arrays.copyOfRange(buf, pos, pos + len);
            pos += len;
            return out;
        }

        byte[] readOctetString() {
            int tag = readTag();
            if (tag != TAG_OCTET_STRING) throw new IllegalArgumentException("Expected OCTET STRING");
            int len = readLength();
            return readBytes(len);
        }

        byte[] readSequenceBytes() {
            int tag = readTag();
            if (tag != TAG_SEQUENCE) throw new IllegalArgumentException("Expected SEQUENCE");
            int len = readLength();
            return readBytes(len);
        }
    }

    /** Unwrap one outer OCTET STRING layer (used for X509Certificate.getExtensionValue output). */
    private static byte[] unwrapOuterOctetString(byte[] der) {
        if (der == null) return null;
        DerReader r = new DerReader(der);
        try { return r.readOctetString(); } catch (RuntimeException e) { return null; }
    }

    /** Subject Key Identifier (2.5.29.14) → keyIdentifier bytes (or null). */
    public static byte[] getSubjectKeyIdentifier(X509Certificate cert) {
        try {
            byte[] ext = cert.getExtensionValue("2.5.29.14");
            byte[] inner = unwrapOuterOctetString(ext);
            if (inner == null || inner.length == 0) return null;

            // RFC 5280: extnValue is OCTET STRING of OCTET STRING (keyIdentifier)
            // Try to unwrap a second time if it looks like an OCTET STRING
            if ((inner[0] & 0xFF) == TAG_OCTET_STRING) {
                return new DerReader(inner).readOctetString();
            }
            // Some CAs provide raw keyIdentifier without the extra wrapper
            return inner;
        } catch (Exception ignore) {
            return null;
        }
    }

    /** Authority Key Identifier (2.5.29.35) → keyIdentifier bytes if present (or null). */
    public static byte[] getAuthorityKeyIdentifier(X509Certificate cert) {
        try {
            byte[] ext = cert.getExtensionValue("2.5.29.35");
            byte[] seqBytes = unwrapOuterOctetString(ext);              // unwrap outer OCTET STRING
            if (seqBytes == null) return null;

            DerReader seq = new DerReader(seqBytes);
            // AKI ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL, ... }
            int tag = seq.readTag();
            if (tag != TAG_SEQUENCE) {
                // Some encoders include tag+len already in seqBytes; handle that:
                // If first tag is [0], treat whole as constructed fragment
                if (tag == TAG_CTX0_PRIM || tag == TAG_CTX0_CONS) {
                    seq.pos = 0; // reset; handle generically below
                } else {
                    // Fallback: try reading as sequence anyway
                    seq = new DerReader(seqBytes);
                }
            } else {
                // step back to parse inside sequence
                seq = new DerReader(seqBytes);
                seq.readSequenceBytes(); // consume sequence header and content into bytes
                // re-init inner reader over content
                seq = new DerReader(seqBytes); // but we need children; simpler approach:
                // Instead of nested readers, parse sequentially:
                // We'll iterate over elements: tag/len/value
            }

            // Simple loop over remaining elements; find context-specific [0]
            DerReader r = new DerReader(seqBytes);
            int t = r.readTag();
            if (t == TAG_SEQUENCE) {
                int l = r.readLength();
                byte[] content = r.readBytes(l);
                r = new DerReader(content);
            } else {
                // Not a sequence; continue with r as-is
                r = new DerReader(seqBytes);
            }

            while (r.hasRemaining()) {
                int et = r.readTag();
                int el = r.readLength();
                if (et == TAG_CTX0_PRIM) {
                    return r.readBytes(el);                      // IMPLICIT OCTET STRING bytes
                } else if (et == TAG_CTX0_CONS) {
                    // Constructed [0]: inside should be an OCTET STRING
                    DerReader inner = new DerReader(r.readBytes(el));
                    try { return inner.readOctetString(); } catch (RuntimeException e) { return null; }
                } else {
                    // skip unknown element
                    r.readBytes(el);
                }
            }
            return null;
        } catch (Exception ignore) {
            return null;
        }
    }

    /** True if KeyUsage has keyCertSign (bit 5) set */
    public static boolean hasKeyUsageKeyCertSign(X509Certificate cert) {
        boolean[] ku = cert.getKeyUsage();
        return ku != null && ku.length > 5 && ku[5];
    }
}