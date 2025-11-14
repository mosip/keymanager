package io.mosip.kernel.partnercertservice.service.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.*;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import java.util.concurrent.TimeUnit;

import io.mosip.kernel.core.util.DateUtils2;
import jakarta.annotation.PostConstruct;
import javax.security.auth.x500.X500Principal;

import org.cache2k.Cache;
import org.cache2k.Cache2kBuilder;
import org.cache2k.expiry.Expiry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.mosip.kernel.core.keymanager.model.CertificateParameters;
import io.mosip.kernel.core.keymanager.spi.ECKeyStore;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanager.hsm.util.CertificateUtility;
import io.mosip.kernel.keymanagerservice.dto.SignatureCertificate;
import io.mosip.kernel.keymanagerservice.entity.PartnerCertificateStore;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.partnercertservice.constant.PartnerCertManagerConstants;
import io.mosip.kernel.partnercertservice.constant.PartnerCertManagerErrorConstants;
import io.mosip.kernel.partnercertservice.dto.CACertificateRequestDto;
import io.mosip.kernel.partnercertservice.dto.CACertificateResponseDto;
import io.mosip.kernel.partnercertservice.dto.CertificateTrustRequestDto;
import io.mosip.kernel.partnercertservice.dto.CertificateTrustResponeDto;
import io.mosip.kernel.partnercertservice.dto.PartnerCertDownloadRequestDto;
import io.mosip.kernel.partnercertservice.dto.PartnerCertDownloadResponeDto;
import io.mosip.kernel.partnercertservice.dto.PartnerCertificateRequestDto;
import io.mosip.kernel.partnercertservice.dto.PartnerCertificateResponseDto;
import io.mosip.kernel.partnercertservice.dto.PartnerSignedCertDownloadResponseDto;
import io.mosip.kernel.keymanagerservice.entity.CACertificateStore;
import io.mosip.kernel.keymanagerservice.repository.CACertificateStoreRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository;
import io.mosip.kernel.partnercertservice.helper.CACertificateStoreSpec;
import io.mosip.kernel.partnercertservice.constant.CaCertificateTypeConsts;
import io.mosip.kernel.partnercertservice.dto.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import io.mosip.kernel.partnercertservice.exception.PartnerCertManagerException;
import io.mosip.kernel.partnercertservice.helper.PartnerCertManagerDBHelper;
import io.mosip.kernel.partnercertservice.service.spi.PartnerCertificateManagerService;
import io.mosip.kernel.partnercertservice.util.PartnerCertificateManagerUtil;

/**
 * This class provides the implementation for the methods of
 * PartnerCertificateManagerService interface.
 *
 * @author Mahammed Taheer
 * @since 1.1.2
 *
 */
@Service
@Transactional
public class PartnerCertificateManagerServiceImpl implements PartnerCertificateManagerService {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(PartnerCertificateManagerServiceImpl.class);

    @Value("${mosip.kernel.partner.sign.masterkey.application.id}")
    private String masterSignKeyAppId;

    @Value("${mosip.kernel.partner.allowed.domains}")
    private String partnerAllowedDomains;

    @Value("${mosip.kernel.certificate.sign.algorithm:SHA256withRSA}")
    private String signAlgorithm;

    @Value("${mosip.kernel.partner.issuer.certificate.duration.years:1}")
    private int issuerCertDuration;

    @Value("${mosip.kernel.partner.issuer.certificate.allowed.grace.duration:30}")
    private int gracePeriod;

    @Value("${mosip.kernel.partner.truststore.cache.expire.inMins:120}")
    private long cacheExpireInMins;

    @Value("${mosip.kernel.partner.resign.ftm.domain.certs:false}")
    private boolean resignFTMDomainCerts;

    @Value("${mosip.kernel.partner.truststore.cache.disable:false}")
    private boolean disableTrustStoreCache;

    @Value("${mosip.kernel.partner.cacertificate.upload.minimumvalidity.month:12}")
    private int minValidity;

    @Value("${mosip.kernel.partner.certificate.chain.cache.expire.inMin:1440}")
    private long certChainCacheExpireInMin;

    /**
     * Utility to generate Metadata
     */
    @Autowired
    private KeymanagerUtil keymanagerUtil;

    /**
     * Utility to generate Metadata
     */
    @Autowired
    private PartnerCertManagerDBHelper certDBHelper;

    /**
     * Repository to get CA certificate
     */
    @Autowired
    private CACertificateStoreRepository caCertificateStoreRepository;

    /**
     * Keystore instance to handles and store cryptographic keys.
     */
    @Autowired
    private ECKeyStore keyStore;

    @Autowired
    private KeymanagerService keymanagerService;
    
    private Cache<String, Object> caCertTrustStore = null;
    
    @Autowired
    private CryptomanagerUtils cryptomanagerUtil;

    @Autowired
    private PartnerCertManagerDBHelper partnerCertManagerDBHelper;

    private Cache<String, List<Certificate>> certChainCache;     

    @PostConstruct
    public void init() {
        // Added Cache2kBuilder in the postConstruct because expire value 
        // configured in properties are getting injected after this object creation.
        // Cache2kBuilder constructor is throwing error.
        checkAndUpdateCaCertificateTypeIsNull();
        if (!disableTrustStoreCache) {
                caCertTrustStore = new Cache2kBuilder<String, Object>() {}
                // added hashcode because test case execution failing with IllegalStateException: Cache already created
                .name("caCertTrustStore-" + this.hashCode()) 
                .expireAfterWrite(cacheExpireInMins, TimeUnit.MINUTES)
                .entryCapacity(10)
                .refreshAhead(true)
                .loaderThreadCount(1)
                .loader((partnerDomain) -> {
                        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.EMPTY,
                                PartnerCertManagerConstants.EMPTY, "Loading CA TrustStore Cache for partnerDomain: " + partnerDomain);
                        return certDBHelper.getTrustAnchors(partnerDomain);
                })
                .build();

            certChainCache = new Cache2kBuilder<String, List<Certificate>>() {}
                    .name("certChainCache-" + this.hashCode())
                    .expireAfterWrite(certChainCacheExpireInMin, TimeUnit.MINUTES)
                    .entryCapacity(100)
                    .build();
        }
    }

    private void checkAndUpdateCaCertificateTypeIsNull() {
        List<CACertificateStore> certificates = caCertificateStoreRepository.findByCaCertificateTypeIsNull();
        String caCertificateType;

        for(CACertificateStore certificate : certificates) {
            X509Certificate x509Cert = (X509Certificate) keymanagerUtil.convertToCertificate(certificate.getCertData());

            if(PartnerCertificateManagerUtil.isSelfSignedCertificate(x509Cert)) {
                caCertificateType = String.valueOf(CaCertificateTypeConsts.ROOT);
            } else {
                caCertificateType = String.valueOf(CaCertificateTypeConsts.INTERMEDIATE);
            }

            certificate.setCaCertificateType(caCertificateType);
            caCertificateStoreRepository.saveAndFlush(certificate);
        }
    }

    @Override
    public CACertificateResponseDto uploadCACertificate(CACertificateRequestDto caCertRequestDto) {
        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                PartnerCertManagerConstants.EMPTY, "Uploading CA/Sub-CA Certificate.");

        String certificateData = caCertRequestDto.getCertificateData();
        if (!keymanagerUtil.isValidCertificateData(certificateData)) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                    PartnerCertManagerConstants.EMPTY,
                    "Invalid Certificate Data provided to upload the ca/sub-ca certificate.");
            throw new PartnerCertManagerException(PartnerCertManagerErrorConstants.INVALID_CERTIFICATE.getErrorCode(),
                    PartnerCertManagerErrorConstants.INVALID_CERTIFICATE.getErrorMessage());
        }

        List<Certificate> certList = parseCertificateData(certificateData);
        int certsCount = certList.size();
        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                    PartnerCertManagerConstants.EMPTY, "Number of Certificates inputed: " + certsCount);

        String partnerDomain = validateAllowedDomains(caCertRequestDto.getPartnerDomain());
        boolean foundError = false;
        boolean uploadedCert = false;
        for(Certificate cert : certList) {
            X509Certificate reqX509Cert = (X509Certificate) cert;

            String certThumbprint = PartnerCertificateManagerUtil.getCertificateThumbprint(reqX509Cert);

            foundError = validateBasicCaCertificateParams(reqX509Cert, certThumbprint, certsCount, partnerDomain);
            if (foundError)
                continue;

            String certSubject = PartnerCertificateManagerUtil
                    .formatCertificateDN(reqX509Cert.getSubjectX500Principal().getName());
            String certIssuer = PartnerCertificateManagerUtil
                    .formatCertificateDN(reqX509Cert.getIssuerX500Principal().getName());
            boolean selfSigned = PartnerCertificateManagerUtil.isSelfSignedCertificate(reqX509Cert);

            if (selfSigned) {
                LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                        PartnerCertManagerConstants.EMPTY, "Adding Self-signed Certificate in store.");
                String certId = UUID.randomUUID().toString();
                String caCertificateType = String.valueOf(CaCertificateTypeConsts.ROOT);
                certDBHelper.storeCACertificate(certId, certSubject, certIssuer, certId, reqX509Cert, certThumbprint,
                        partnerDomain, caCertificateType);
                uploadedCert = true;

            } else {
                LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                        PartnerCertManagerConstants.EMPTY, "Adding Intermediate Certificates in store.");

                boolean certValid = validateCertificatePath(reqX509Cert, partnerDomain);
                if (!certValid) {
                     LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                           PartnerCertManagerConstants.EMPTY,
                           "Sub-CA Certificate not allowed to upload as root CA is not available.");
                     if (certsCount == 1) {
                        throw new PartnerCertManagerException(PartnerCertManagerErrorConstants.ROOT_CA_NOT_FOUND.getErrorCode(),
                            PartnerCertManagerErrorConstants.ROOT_CA_NOT_FOUND.getErrorMessage());
                     }
                     foundError = true;
                     continue;
                }
                String issuerId = certDBHelper.getIssuerCertId(certIssuer);
                String certId = UUID.randomUUID().toString();
                String caCertificateType = String.valueOf(CaCertificateTypeConsts.INTERMEDIATE);
                certDBHelper.storeCACertificate(certId, certSubject, certIssuer, issuerId, reqX509Cert, certThumbprint,
                        partnerDomain, caCertificateType);
                uploadedCert = true;
            }
            purgeCache(partnerDomain);
        }
        CACertificateResponseDto responseDto = new CACertificateResponseDto();
        if (uploadedCert && (certsCount == 1 || !foundError))
            responseDto.setStatus(PartnerCertManagerConstants.SUCCESS_UPLOAD);
        else if (uploadedCert && foundError)
            responseDto.setStatus(PartnerCertManagerConstants.PARTIAL_SUCCESS_UPLOAD);
        else 
            responseDto.setStatus(PartnerCertManagerConstants.UPLOAD_FAILED);
        responseDto.setTimestamp(DateUtils2.getUTCCurrentDateTime());
        return responseDto;
    }

    private List<Certificate> parseCertificateData(String certificateData) {
        List<Certificate> certList = new ArrayList<>();
        try {
            X509Certificate reqX509Cert = (X509Certificate) keymanagerUtil.convertToCertificate(certificateData);
            certList.add(reqX509Cert);
            return certList;
        } catch(KeymanagerServiceException kse) {
            LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                PartnerCertManagerConstants.EMPTY, "Ignore this exception, the exception thrown when certificate is not" 
                                        + " able to parse, may be p7b certificate data inputed.");
        }
        // Try to Parse as P7B file.
        byte[] p7bBytes = CryptoUtil.decodeURLSafeBase64(certificateData);
        try (ByteArrayInputStream certStream = new ByteArrayInputStream(p7bBytes)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<?> p7bCertList = cf.generateCertificates(certStream);
            p7bCertList.forEach(cert -> {
                certList.add((Certificate)cert);
            });
            Collections.reverse(certList);
            return certList;
        } catch(CertificateException | IOException  exp) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                PartnerCertManagerConstants.EMPTY, "Error Parsing P7B Certificate data.", exp);
        }
        throw new PartnerCertManagerException(
                PartnerCertManagerErrorConstants.INVALID_CERTIFICATE.getErrorCode(),
                PartnerCertManagerErrorConstants.INVALID_CERTIFICATE.getErrorMessage());
    }

    private String validateAllowedDomains(String partnerDomain) {
        String validPartnerDomain = Stream.of(partnerAllowedDomains.split(",")).map(String::trim)
                .filter(allowedDomain -> allowedDomain.equalsIgnoreCase(partnerDomain)).findFirst()
                .orElseThrow(() -> new PartnerCertManagerException(
                        PartnerCertManagerErrorConstants.INVALID_PARTNER_DOMAIN.getErrorCode(),
                        PartnerCertManagerErrorConstants.INVALID_PARTNER_DOMAIN.getErrorMessage()));
        return validPartnerDomain.toUpperCase();
    }

    private String validateAllowedCaCertificateType(String caCertificateType) {
        boolean isValidCaCertType = Arrays.stream(CaCertificateTypeConsts.values()).anyMatch((caCertType) -> caCertType.name()
                .equalsIgnoreCase(caCertificateType));
        if(!isValidCaCertType) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.EMPTY, caCertificateType,
                    "Invalid CA Certificate Type", PartnerCertManagerErrorConstants.INVALID_CA_CERTIFICATE_TYPE);
            throw new PartnerCertManagerException(
                    PartnerCertManagerErrorConstants.INVALID_CA_CERTIFICATE_TYPE.getErrorCode(),
                    PartnerCertManagerErrorConstants.INVALID_CA_CERTIFICATE_TYPE.getErrorMessage()
            );
        }
        return caCertificateType.toUpperCase();
    }

    @SuppressWarnings({"unchecked", "java:S2259"}) // added suppress for sonarcloud, not possibility of null pointer exception.
    private List<? extends Certificate> getCertificateTrustPath(X509Certificate reqX509Cert, String partnerDomain, Set<X509Certificate> interCertsTrust) {

        try {
            final String cacheKey = partnerDomain + PartnerCertManagerConstants.SEPERATOR + PartnerCertificateManagerUtil.getCertificateThumbprint(reqX509Cert);

            List<? extends Certificate> cachedChain = certChainCache.get(cacheKey);
            if (cachedChain != null) {
                LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.CERT_TRUST_VALIDATION,
                        PartnerCertManagerConstants.EMPTY, "Certificate Trust Path Validation found in cache for domain and thumbprint: " + cacheKey);
                return cachedChain;
            }

            LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.CERT_TRUST_VALIDATION,
                    PartnerCertManagerConstants.EMPTY, "Certificate Trust Path Validation not found in cache for domain and thumbprint: " + cacheKey);

            Map<String, Set<?>> trustStoreMap = !disableTrustStoreCache ? (Map<String, Set<?>>) caCertTrustStore.get(partnerDomain):
                    certDBHelper.getTrustAnchors(partnerDomain);
            Set<TrustAnchor> rootTrustAnchors = (Set<TrustAnchor>) trustStoreMap
                    .get(PartnerCertManagerConstants.TRUST_ROOT);
            Set<X509Certificate> interCerts = interCertsTrust == null ? (Set<X509Certificate>) trustStoreMap
                    .get(PartnerCertManagerConstants.TRUST_INTER) : interCertsTrust;

            LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.CERT_TRUST_VALIDATION,
                    PartnerCertManagerConstants.EMPTY, "Certificate Trust Path Validation for domain: " + partnerDomain);
            LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.CERT_TRUST_VALIDATION,
                    PartnerCertManagerConstants.EMPTY, "Total Number of ROOT Trust Found: " + rootTrustAnchors.size());
            LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.CERT_TRUST_VALIDATION,
                    PartnerCertManagerConstants.EMPTY, "Total Number of INTERMEDIATE Trust Found: " + interCerts.size());

            X509CertSelector certToVerify = new X509CertSelector();
            certToVerify.setCertificate(reqX509Cert);

            PKIXBuilderParameters pkixBuilderParams = new PKIXBuilderParameters(rootTrustAnchors, certToVerify);
            pkixBuilderParams.setRevocationEnabled(false);

            CertStore interCertStore = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(interCerts));
            pkixBuilderParams.addCertStore(interCertStore);

            // Building the cert path and verifying the certification chain
            CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
            //certPathBuilder.build(pkixBuilderParams);
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) certPathBuilder.build(pkixBuilderParams);

            X509Certificate rootCert = result.getTrustAnchor().getTrustedCert();
            List<? extends Certificate> certList = result.getCertPath().getCertificates();
            List<Certificate> trustCertList = new ArrayList<>();
            certList.stream().forEach(cert -> {
                trustCertList.add(cert);
            });
            trustCertList.add(rootCert);

            certChainCache.put(cacheKey, trustCertList);
            LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.CERT_TRUST_VALIDATION,
                    PartnerCertManagerConstants.EMPTY, "Certificate Chain stored in cache, key: {}", cacheKey);
            return trustCertList;
        } catch (CertPathBuilderException | InvalidAlgorithmParameterException | NoSuchAlgorithmException exp) {
            LOGGER.debug(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                    PartnerCertManagerConstants.EMPTY,
                    "Ignore this exception, the exception thrown when trust validation failed.");
        }
        return null;
    }

    @Override
    public List<? extends Certificate> getCertificateTrustChain(X509Certificate reqX509Cert, String partnerDomain, Set<X509Certificate> interCertsTrust) {
        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.CERT_TRUST_VALIDATION,
                PartnerCertManagerConstants.EMPTY, "Certificate Trust chain for domain: " + partnerDomain);
        return getCertificateTrustPath(reqX509Cert, partnerDomain, interCertsTrust);
    }

    private boolean validateCertificatePath(X509Certificate reqX509Cert, String partnerDomain) {
        List<? extends Certificate> certList = getCertificateTrustPath(reqX509Cert, partnerDomain, null);
        return Objects.nonNull(certList);
    }

    public boolean validateCertificatePathWithInterCertTrust(X509Certificate reqX509Cert, String partnerDomain, Set<X509Certificate> interCerts) {
        List<? extends Certificate> certList = getCertificateTrustPath(reqX509Cert, partnerDomain, interCerts);
        return Objects.nonNull(certList);
    }

    @Override
    public PartnerCertificateResponseDto uploadPartnerCertificate(PartnerCertificateRequestDto partnerCertRequesteDto) {
        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                PartnerCertManagerConstants.EMPTY, "Uploading Partner Certificate.");

        String certificateData = partnerCertRequesteDto.getCertificateData();
        if (!keymanagerUtil.isValidCertificateData(certificateData)) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                    PartnerCertManagerConstants.EMPTY,
                    "Invalid Certificate Data provided to upload the partner certificate.");
            throw new PartnerCertManagerException(PartnerCertManagerErrorConstants.INVALID_CERTIFICATE.getErrorCode(),
                    PartnerCertManagerErrorConstants.INVALID_CERTIFICATE.getErrorMessage());
        }

        X509Certificate reqX509Cert = (X509Certificate) keymanagerUtil.convertToCertificate(certificateData);
        String certThumbprint = PartnerCertificateManagerUtil.getCertificateThumbprint(reqX509Cert);
        String reqOrgName = partnerCertRequesteDto.getOrganizationName();
        String partnerDomain = validateAllowedDomains(partnerCertRequesteDto.getPartnerDomain());

        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                PartnerCertManagerConstants.EMPTY, "Partner certificate upload for domain: " + partnerDomain);

        validateBasicPartnerCertParams(reqX509Cert, certThumbprint, reqOrgName, partnerDomain);

        List<? extends Certificate> certList = getCertificateTrustPath(reqX509Cert, partnerDomain, null);
        //boolean certValid = validateCertificatePath(reqX509Cert, partnerDomain);
        if (Objects.isNull(certList)) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                    PartnerCertManagerConstants.EMPTY,
                    "Partner Certificate not allowed to upload as root CA/Intermediate CAs are not found in trust cert path.");
            throw new PartnerCertManagerException(
                    PartnerCertManagerErrorConstants.ROOT_INTER_CA_NOT_FOUND.getErrorCode(),
                    PartnerCertManagerErrorConstants.ROOT_INTER_CA_NOT_FOUND.getErrorMessage());
        }
        validateOtherPartnerCertParams(reqX509Cert, reqOrgName);

        String certSubject = PartnerCertificateManagerUtil
                .formatCertificateDN(reqX509Cert.getSubjectX500Principal().getName());
        String certIssuer = PartnerCertificateManagerUtil
                .formatCertificateDN(reqX509Cert.getIssuerX500Principal().getName());
        String issuerId = certDBHelper.getIssuerCertId(certIssuer);
        String certId = UUID.randomUUID().toString();

        X509Certificate rootCert = (X509Certificate) keymanagerUtil.convertToCertificate(
                                        keymanagerService.getCertificate(PartnerCertManagerConstants.ROOT_APP_ID, 
                                                        Optional.of(PartnerCertManagerConstants.EMPTY)).getCertificate());
        String timestamp = DateUtils2.getUTCCurrentDateTimeString();
        SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(masterSignKeyAppId,
                                                        Optional.of(PartnerCertManagerConstants.EMPTY), timestamp);
        X509Certificate pmsCert = certificateResponse.getCertificateEntry().getChain()[0];

        X509Certificate resignedCert = reSignPartnerKey(reqX509Cert, certificateResponse, partnerDomain);
        String signedCertData = keymanagerUtil.getPEMFormatedData(resignedCert);
        certDBHelper.storePartnerCertificate(certId, certSubject, certIssuer, issuerId, reqX509Cert, certThumbprint,
                reqOrgName, partnerDomain, signedCertData);
        
        String p7bCertChain = PartnerCertificateManagerUtil.buildP7BCertificateChain(certList, resignedCert, partnerDomain, 
                        resignFTMDomainCerts, rootCert, pmsCert);
        CACertificateRequestDto caCertReqDto = new CACertificateRequestDto();
        caCertReqDto.setCertificateData(p7bCertChain);
        caCertReqDto.setPartnerDomain(partnerDomain);
        CACertificateResponseDto uploadResponseDto = uploadCACertificate(caCertReqDto);
        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
        "Chain Upload Status: ", uploadResponseDto.getStatus());
        PartnerCertificateResponseDto responseDto = new PartnerCertificateResponseDto();
        responseDto.setCertificateId(certId);
        responseDto.setSignedCertificateData(p7bCertChain);
        responseDto.setTimestamp(DateUtils2.getUTCCurrentDateTime());
        return responseDto;
    }

    private void validateBasicPartnerCertParams(X509Certificate reqX509Cert, String certThumbprint, String reqOrgName,
            String partnerDomain) {
        boolean certExist = certDBHelper.isPartnerCertificateExist(certThumbprint, partnerDomain);
        if (certExist) {
            LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                    PartnerCertManagerConstants.EMPTY, "Partner certificate already exists in Store.");
            // Commented below throw clause because renewal of certificate should be allowed for existing certificates.
            // Added one more condition to check certificate validity is in allowed date range.
            /* throw new PartnerCertManagerException(
                    PartnerCertManagerErrorConstants.CERTIFICATE_EXIST_ERROR.getErrorCode(),
                    PartnerCertManagerErrorConstants.CERTIFICATE_EXIST_ERROR.getErrorMessage()); */
        }

        boolean futureDated = PartnerCertificateManagerUtil.isFutureDatedCertificate(reqX509Cert);
        if (!futureDated) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                    PartnerCertManagerConstants.EMPTY, "Certificate is Future Dated.");
            throw new PartnerCertManagerException(
                    PartnerCertManagerErrorConstants.FUTURE_DATED_CERT_NOT_ALLOWED.getErrorCode(),
                    PartnerCertManagerErrorConstants.FUTURE_DATED_CERT_NOT_ALLOWED.getErrorMessage()
            );
        }

        boolean validDates = PartnerCertificateManagerUtil.isCertificateDatesValid(reqX509Cert);
        if (!validDates) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                    PartnerCertManagerConstants.EMPTY, "Certificate Dates are not valid.");
            throw new PartnerCertManagerException(
                    PartnerCertManagerErrorConstants.CERTIFICATE_DATES_NOT_VALID.getErrorCode(),
                    PartnerCertManagerErrorConstants.CERTIFICATE_DATES_NOT_VALID.getErrorMessage());
        }

        boolean validDuration = PartnerCertificateManagerUtil.isCertificateValidForDuration(reqX509Cert, issuerCertDuration, gracePeriod);
        if (!validDuration) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                    PartnerCertManagerConstants.EMPTY, "Certificate Dates are not in allowed range.");
            throw new PartnerCertManagerException(
                    PartnerCertManagerErrorConstants.PARTNER_CERT_LESS_THAN_MIN_VALIDITY_NOT_ALLOWED.getErrorCode(),
                    PartnerCertManagerErrorConstants.PARTNER_CERT_LESS_THAN_MIN_VALIDITY_NOT_ALLOWED.getErrorMessage());
        }

        boolean selfSigned = PartnerCertificateManagerUtil.isSelfSignedCertificate(reqX509Cert);
        if (selfSigned) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                        PartnerCertManagerConstants.EMPTY, "Self Signed Certificate are not in allowed as Partner.");
            throw new PartnerCertManagerException(
                        PartnerCertManagerErrorConstants.SELF_SIGNED_CERT_NOT_ALLOWED.getErrorCode(),
                        PartnerCertManagerErrorConstants.SELF_SIGNED_CERT_NOT_ALLOWED.getErrorMessage());
        }
    }

    private boolean validateBasicCaCertificateParams(X509Certificate reqX509Cert, String certThumbprint, int certsCount,
                                                  String partnerDomain) {
        boolean foundError = false;
        boolean certExist = certDBHelper.isCertificateExist(certThumbprint, partnerDomain);
            if (certExist) {
                LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                        PartnerCertManagerConstants.EMPTY, "CA/sub-CA certificate already exists in Store.");
                if (certsCount == 1) {
                     throw new PartnerCertManagerException(
                           PartnerCertManagerErrorConstants.CERTIFICATE_EXIST_ERROR.getErrorCode(),
                           PartnerCertManagerErrorConstants.CERTIFICATE_EXIST_ERROR.getErrorMessage());
                }
                foundError = true;
            }

        boolean futureDated = PartnerCertificateManagerUtil.isFutureDatedCertificate(reqX509Cert);
        if (!futureDated) {
            LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                    PartnerCertManagerConstants.EMPTY, "Future Dated Certificate.");
            if (certsCount == 1) {
                throw new PartnerCertManagerException(PartnerCertManagerErrorConstants.FUTURE_DATED_CERT_NOT_ALLOWED.getErrorCode(),
                        PartnerCertManagerErrorConstants.FUTURE_DATED_CERT_NOT_ALLOWED.getErrorMessage());
            }
            foundError = true;
        }

        boolean validDates = PartnerCertificateManagerUtil.isCertificateDatesValid(reqX509Cert);
        if (!validDates) {
            LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                    PartnerCertManagerConstants.EMPTY, "Certificate Dates are not valid.");
            if(certsCount == 1) {
                throw new PartnerCertManagerException(
                        PartnerCertManagerErrorConstants.CERTIFICATE_DATES_NOT_VALID.getErrorCode(),
                        PartnerCertManagerErrorConstants.CERTIFICATE_DATES_NOT_VALID.getErrorMessage());
            }
            foundError = true;
        }

        boolean minimumValidity = PartnerCertificateManagerUtil.isMinValidityCertificate(reqX509Cert, minValidity);
        if(!minimumValidity) {
            LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_CA_CERT,
                    PartnerCertManagerConstants.EMPTY, "Certificate expire before the minimum validity.");
            if (certsCount == 1) {
                throw new PartnerCertManagerException(PartnerCertManagerErrorConstants.CERT_VALIDITY_LESS_THAN_MIN_VALIDITY_NOT_ALLOWED.getErrorCode(),
                        PartnerCertManagerErrorConstants.CERT_VALIDITY_LESS_THAN_MIN_VALIDITY_NOT_ALLOWED.getErrorMessage());
            }
            foundError = true;
        }

        int certVersion = reqX509Cert.getVersion();
        if (certVersion != 3) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                    PartnerCertManagerConstants.EMPTY,
                    "CA Certificate version not valid, the version has to be V3");
                if (certsCount == 1){
                    throw new PartnerCertManagerException(PartnerCertManagerErrorConstants.INVALID_CERT_VERSION.getErrorCode(),
                            PartnerCertManagerErrorConstants.INVALID_CERT_VERSION.getErrorMessage());
                }
                foundError = true;
        }
            return foundError;
    }

    private void validateOtherPartnerCertParams(X509Certificate reqX509Cert, String reqOrgName) {
        int certVersion = reqX509Cert.getVersion();
        if (certVersion != 3) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                    PartnerCertManagerConstants.EMPTY,
                    "Partner Certificate version not valid, the version has to be V3");
            throw new PartnerCertManagerException(PartnerCertManagerErrorConstants.INVALID_CERT_VERSION.getErrorCode(),
                    PartnerCertManagerErrorConstants.INVALID_CERT_VERSION.getErrorMessage());
        }

        String certOrgName = PartnerCertificateManagerUtil.getCertificateOrgName(reqX509Cert.getSubjectX500Principal());
        if (certOrgName.equals(PartnerCertManagerConstants.EMPTY)) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                    PartnerCertManagerConstants.EMPTY,
                    "Partner Certificate Organization is not available/empty input certificate.");
            throw new PartnerCertManagerException(PartnerCertManagerErrorConstants.PARTNER_ORG_NOT_MATCH.getErrorCode(),
                    PartnerCertManagerErrorConstants.PARTNER_ORG_NOT_MATCH.getErrorMessage());
        }

        if (!certOrgName.equals(reqOrgName)) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                    PartnerCertManagerConstants.EMPTY,
                    "Partner Certificate Organization and Partner Organization Name not matching.");
            throw new PartnerCertManagerException(PartnerCertManagerErrorConstants.PARTNER_ORG_NOT_MATCH.getErrorCode(),
                    PartnerCertManagerErrorConstants.PARTNER_ORG_NOT_MATCH.getErrorMessage());
        }

        String keyAlgorithm = reqX509Cert.getPublicKey().getAlgorithm();
        if (keyAlgorithm.equalsIgnoreCase(PartnerCertManagerConstants.RSA_ALGORITHM)) {
            int keySize = ((java.security.interfaces.RSAPublicKey) reqX509Cert.getPublicKey()).getModulus().bitLength();
            if (keySize < PartnerCertManagerConstants.RSA_MIN_KEY_SIZE) {
                LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                        PartnerCertManagerConstants.EMPTY, "Partner Certificate key is less than allowed size.");
                throw new PartnerCertManagerException(
                        PartnerCertManagerErrorConstants.CERT_KEY_NOT_ALLOWED.getErrorCode(),
                        PartnerCertManagerErrorConstants.CERT_KEY_NOT_ALLOWED.getErrorMessage());
            }
        }

        String signatureAlgorithm = reqX509Cert.getSigAlgName();
        if (!signatureAlgorithm.toUpperCase().startsWith(PartnerCertManagerConstants.HASH_SHA2)) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                    PartnerCertManagerConstants.EMPTY, "Signature Algorithm not supported.");
            throw new PartnerCertManagerException(
                    PartnerCertManagerErrorConstants.CERT_SIGNATURE_ALGO_NOT_ALLOWED.getErrorCode(),
                    PartnerCertManagerErrorConstants.CERT_SIGNATURE_ALGO_NOT_ALLOWED.getErrorMessage());
        }
    }

    private X509Certificate reSignPartnerKey(X509Certificate reqX509Cert, SignatureCertificate certificateResponse, 
                        String partnerDomain) {

        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT, "KeyAlias",
                "Found Master Key Alias: " + certificateResponse.getAlias());
        
        boolean hasAcccess = cryptomanagerUtil.hasKeyAccess(masterSignKeyAppId);
        if (!hasAcccess) {
                LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT, PartnerCertManagerConstants.EMPTY,
                        "Signing Certifiate is not allowed for the authenticated user for the provided application id.");
                throw new PartnerCertManagerException(PartnerCertManagerErrorConstants.SIGN_CERT_NOT_ALLOWED.getErrorCode(),
                        PartnerCertManagerErrorConstants.SIGN_CERT_NOT_ALLOWED.getErrorMessage());
        }
        PrivateKey signPrivateKey = certificateResponse.getCertificateEntry().getPrivateKey();
        X509Certificate signCert = certificateResponse.getCertificateEntry().getChain()[0];
        X500Principal signerPrincipal = signCert.getSubjectX500Principal();

        X500Principal subjectPrincipal = reqX509Cert.getSubjectX500Principal();
        PublicKey partnerPublicKey = reqX509Cert.getPublicKey();
        
        int noOfDays = PartnerCertManagerConstants.YEAR_DAYS * issuerCertDuration;
        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT, "Cert Duration",
                "Calculated Signed Certficiate Number of Days for expire: " + noOfDays);
        LocalDateTime notBeforeDate = DateUtils2.getUTCCurrentDateTime();
        LocalDateTime notAfterDate = notBeforeDate.plus(noOfDays, ChronoUnit.DAYS);
        CertificateParameters certParams = PartnerCertificateManagerUtil.getCertificateParameters(subjectPrincipal,
                notBeforeDate, notAfterDate);
        boolean encKeyUsage = partnerDomain.equalsIgnoreCase(PartnerCertManagerConstants.AUTH_DOMAIN);
        return (X509Certificate) CertificateUtility.generateX509Certificate(signPrivateKey, partnerPublicKey, certParams,
                signerPrincipal, signAlgorithm, keyStore.getKeystoreProviderName(), encKeyUsage);
    }

    @Override
    public PartnerCertDownloadResponeDto getPartnerCertificate(PartnerCertDownloadRequestDto certDownloadRequestDto) {

        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.GET_PARTNER_CERT,
                PartnerCertManagerConstants.EMPTY, "Get Partner Certificate Request.");

        String partnetCertId = certDownloadRequestDto.getPartnerCertId();
        PartnerCertificateStore partnerCertStore = getPartnerCertificate(partnetCertId);

        PartnerCertDownloadResponeDto responseDto = new PartnerCertDownloadResponeDto();
        responseDto.setCertificateData(partnerCertStore.getSignedCertData());
        responseDto.setTimestamp(DateUtils2.getUTCCurrentDateTime());
        return responseDto;
    }

    @Override
    public CertificateTrustResponeDto verifyCertificateTrust(CertificateTrustRequestDto certificateTrustRequestDto) {
        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.CERT_TRUST_VALIDATION,
                PartnerCertManagerConstants.EMPTY, "Certificate Trust Path Validation.");

        String certificateData = certificateTrustRequestDto.getCertificateData();
        if (!keymanagerUtil.isValidCertificateData(certificateData)) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                    PartnerCertManagerConstants.EMPTY,
                    "Invalid Certificate Data provided to verify partner certificate trust.");
            throw new PartnerCertManagerException(PartnerCertManagerErrorConstants.INVALID_CERTIFICATE.getErrorCode(),
                    PartnerCertManagerErrorConstants.INVALID_CERTIFICATE.getErrorMessage());
        }
        X509Certificate reqX509Cert = (X509Certificate) keymanagerUtil.convertToCertificate(certificateData);
        String partnerDomain = validateAllowedDomains(certificateTrustRequestDto.getPartnerDomain());

        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.CERT_TRUST_VALIDATION,
                PartnerCertManagerConstants.EMPTY, "Certificate Trust Path Validation for domain: " + partnerDomain);

        boolean certValid = validateCertificatePath(reqX509Cert, partnerDomain);
        CertificateTrustResponeDto responseDto = new CertificateTrustResponeDto();
        responseDto.setStatus(certValid);     
        return responseDto;
    }
    
    @Override
    public void purgeTrustStoreCache(String partnerDomain) {
        purgeCache(partnerDomain);
        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT, PartnerCertManagerConstants.EMPTY,
                "Trust Store Cache Purge for partner domain " + partnerDomain);
    }

    private void purgeCache(String partnerDomain) {
        if(!disableTrustStoreCache) {
            caCertTrustStore.expireAt(partnerDomain, Expiry.NOW);
        }
    }

    @Override
    public PartnerSignedCertDownloadResponseDto getPartnerSignedCertificate(PartnerCertDownloadRequestDto certDownloadRequestDto) {

        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.GET_PARTNER_CERT,
                PartnerCertManagerConstants.EMPTY, "Get Partner CA Signed Certificate & " +
                        "Mosip Signed Certificate Request.");

        String partnetCertId = certDownloadRequestDto.getPartnerCertId();
        PartnerCertificateStore partnerCertStore = getPartnerCertificate(partnetCertId);

        PartnerSignedCertDownloadResponseDto responseDto = new PartnerSignedCertDownloadResponseDto();
        responseDto.setMosipSignedCertificateData(partnerCertStore.getSignedCertData());
        responseDto.setCaSignedCertificateData(partnerCertStore.getCertData());
        responseDto.setTimestamp(DateUtils2.getUTCCurrentDateTime());
        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.GET_PARTNER_CERT,
                PartnerCertManagerConstants.EMPTY, "Get Partner CA Signed Certificate & " +
                        "Mosip Signed Certificate Request. - Completed");
        return responseDto;
    }

    @Override
    public CACertificateTrustPathResponseDto getCACertificateTrustPath(CACertificateTrustPathRequestDto caCertificateTrustPathRequestDto) {


        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.GET_CA_CERT_TRUST,
                PartnerCertManagerConstants.EMPTY, "Get CA Certificate with trust request: " );

        String caCertId = caCertificateTrustPathRequestDto.getCaCertId();
        CACertificateStore caCertificateStore = getCACertificate(caCertId);
        X509Certificate caCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(String.valueOf(caCertificateStore.getCertData()));
        String partnerDomain = caCertificateStore.getPartnerDomain();
        LocalDateTime timestamp = DateUtils2.getUTCCurrentDateTime();
        List<? extends Certificate> certList = null;
        List<Certificate> chain = new ArrayList<>();

        if (PartnerCertificateManagerUtil.isSelfSignedCertificate(caCertificate)){
            chain.add(caCertificate);
        } else {
            certList = getCertificateTrustPath(caCertificate, partnerDomain, null);
        }

        if (certList != null) {
            chain.addAll(certList);
        }
        String buildTrustPath = PartnerCertificateManagerUtil.buildp7bFile(chain.toArray(new Certificate[0]));

        CACertificateTrustPathResponseDto responseDto = new CACertificateTrustPathResponseDto();
        responseDto.setP7bFile(buildTrustPath);
        responseDto.setTimestamp(timestamp);
        return responseDto;
    }

    private CACertificateStore getCACertificate(String caCertId) {
        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.GET_CA_CERT, PartnerCertManagerConstants.EMPTY,
                "Request to get CA Certificate for caCertId: " + caCertId);

        if (!PartnerCertificateManagerUtil.isValidCertificateID(caCertId)) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.GET_CA_CERT,
                    PartnerCertManagerConstants.EMPTY, "Invalid CA Certificate ID provided to get the CA Certificate.");
            throw new PartnerCertManagerException(
                    PartnerCertManagerErrorConstants.INVALID_CERTIFICATE_ID.getErrorCode(),
                    PartnerCertManagerErrorConstants.INVALID_CERTIFICATE_ID.getErrorMessage());
        }
        CACertificateStore caCertificateStore = certDBHelper.getCACert(caCertId);
        if (Objects.isNull(caCertificateStore)) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.GET_CA_CERT,
                    PartnerCertManagerConstants.EMPTY, "CA Certificate not found for the provided ID.");
            throw new PartnerCertManagerException(
                    PartnerCertManagerErrorConstants.CA_CERT_ID_NOT_FOUND.getErrorCode(),
                    PartnerCertManagerErrorConstants.CA_CERT_ID_NOT_FOUND.getErrorMessage());
        }
        return caCertificateStore;
    }

    private PartnerCertificateStore getPartnerCertificate(String partnetCertId) {
        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.GET_PARTNER_CERT, PartnerCertManagerConstants.EMPTY,
                "Request to get Certificate for partnerId: " + partnetCertId);        

        if (!PartnerCertificateManagerUtil.isValidCertificateID(partnetCertId)) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                    PartnerCertManagerConstants.EMPTY,
                    "Invalid Certificate ID provided to get the partner certificate.");
            throw new PartnerCertManagerException(
                    PartnerCertManagerErrorConstants.INVALID_CERTIFICATE_ID.getErrorCode(),
                    PartnerCertManagerErrorConstants.INVALID_CERTIFICATE_ID.getErrorMessage());
        }
        PartnerCertificateStore partnerCertStore = certDBHelper.getPartnerCert(partnetCertId);
        if (Objects.isNull(partnerCertStore)) {
            LOGGER.error(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.UPLOAD_PARTNER_CERT,
                    PartnerCertManagerConstants.EMPTY, "Partner Certificate not found for the provided ID.");
            throw new PartnerCertManagerException(
                    PartnerCertManagerErrorConstants.PARTNER_CERT_ID_NOT_FOUND.getErrorCode(),
                    PartnerCertManagerErrorConstants.PARTNER_CERT_ID_NOT_FOUND.getErrorMessage());
        }
        return partnerCertStore;
    }

    @Override
    public CaCertificateChainResponseDto getCaCertificateChain(CaCertTypeListRequestDto requestDto) {
        LOGGER.info(PartnerCertManagerConstants.SESSIONID, PartnerCertManagerConstants.GET_PARTNER_CERT, requestDto.getCaCertificateType(),
                "Request to get Certificate for Domain and Certificate Type: " + requestDto.getPartnerDomain());

        Boolean excludeMosipCert = requestDto.getExcludeMosipCA() == null ? Boolean.FALSE : requestDto.getExcludeMosipCA();
        String partnerDomain = PartnerCertificateManagerUtil.handleNullOrEmpty(requestDto.getPartnerDomain()) == null ? null : validateAllowedDomains(requestDto.getPartnerDomain());
        String caCertificateType = PartnerCertificateManagerUtil.handleNullOrEmpty(requestDto.getCaCertificateType()) == null ? null : validateAllowedCaCertificateType(requestDto.getCaCertificateType());
        int offSet = requestDto.getPageNumber() < 1 ? 0 : requestDto.getPageNumber() - 1;
        int pageSize = requestDto.getPageSize() < 1 ? 10 : requestDto.getPageSize();
        String certId = PartnerCertificateManagerUtil.handleNullOrEmpty(requestDto.getCertId());
        String issuedTo = PartnerCertificateManagerUtil.handleNullOrEmpty(requestDto.getIssuedTo());
        String issuedBy = PartnerCertificateManagerUtil.handleNullOrEmpty(requestDto.getIssuedBy());
        LocalDateTime validFrom = requestDto.getValidFromDate();
        LocalDateTime validTill = requestDto.getValidTillDate();
        LocalDateTime uploadTime = requestDto.getUploadTime();
        LocalDateTime expiringWithinDate = requestDto.getExpiringWithinDate();
        String sortFieldName = PartnerCertificateManagerUtil.handleNullOrEmpty(requestDto.getSortByFieldName()) == null ? "createdtimes" : requestDto.getSortByFieldName();

        Sort.Direction direction = "DESC".equalsIgnoreCase(requestDto.getSortOrder()) ? Sort.Direction.DESC : Sort.Direction.ASC;
        PageRequest pageRequest = PageRequest.of(offSet, pageSize, Sort.by(direction, sortFieldName));

        List<String> certThumbprints = getMosipCertThumbprints(excludeMosipCert);

        Specification<CACertificateStore> spec = CACertificateStoreSpec.filterCertificates(
                caCertificateType, partnerDomain, certId, issuedTo, issuedBy, validFrom, validTill, uploadTime, expiringWithinDate, certThumbprints);

        Page<CACertificateStore> partnerCertificateList = caCertificateStoreRepository.findAll(spec, pageRequest);

        CaCertTypeListResponseDto[] certificates = partnerCertificateList.getContent()
                .stream()
                .map(certificate -> {
                    CaCertTypeListResponseDto certResponseDto = new CaCertTypeListResponseDto();
                    certResponseDto.setCaCertificateType(certificate.getCaCertificateType());
                    certResponseDto.setPartnerDomain(certificate.getPartnerDomain());
                    certResponseDto.setCertId(certificate.getCertId());
                    certResponseDto.setIssuedTo(certificate.getCertSubject());
                    certResponseDto.setIssuedBy(certificate.getCertIssuer());
                    certResponseDto.setCertThumbprint(certificate.getCertThumbprint());
                    certResponseDto.setValidFromDate(certificate.getCertNotBefore());
                    certResponseDto.setValidTillDate(certificate.getCertNotAfter());
                    certResponseDto.setUploadTime(certificate.getCreatedtimes());
                    certResponseDto.setStatus(isActiveCaCert(certificate));
                    return certResponseDto;
                })
                .toArray(CaCertTypeListResponseDto[]::new);

        CaCertificateChainResponseDto responseDto = new CaCertificateChainResponseDto();
        responseDto.setAllPartnerCertificates(certificates);
        responseDto.setPageNumber(partnerCertificateList.getNumber() + 1);
        responseDto.setPageSize(partnerCertificateList.getSize());
        responseDto.setTotalRecords(partnerCertificateList.getTotalElements());
        responseDto.setTotalPages(partnerCertificateList.getTotalPages());

        return responseDto;
    }

    private List<String> getMosipCertThumbprints(boolean excludeMosipcert) {
        List<String> certThumbprints = new ArrayList<>();
        if (excludeMosipcert) {
            partnerCertManagerDBHelper.getCertThumbprints(PartnerCertManagerConstants.ROOT_APP_ID,
                    Optional.of(PartnerCertManagerConstants.EMPTY), certThumbprints);

            partnerCertManagerDBHelper.getCertThumbprints(PartnerCertManagerConstants.PMS_APP_ID,
                    Optional.of(PartnerCertManagerConstants.EMPTY), certThumbprints);
        }
        return certThumbprints;
    }

    private boolean isActiveCaCert(CACertificateStore certificate) {
        LocalDateTime timeStamp = DateUtils2.getUTCCurrentDateTime();
        return timeStamp.isEqual(certificate.getCertNotBefore()) || timeStamp.isEqual(certificate.getCertNotAfter())
                || (timeStamp.isAfter(certificate.getCertNotBefore()) && timeStamp.isBefore(certificate.getCertNotAfter()));
    }
}
