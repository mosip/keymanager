package io.mosip.kernel.partnercertservice.service.spi;

import io.mosip.kernel.partnercertservice.dto.*;

/**
 * This interface provides the methods for Partner Certificate Management Service.
 * 
 * @author Mahammed Taheer
 * @since 1.1.2
 *
 */

public interface PartnerCertificateManagerService {
    
    /**
	 * Function to Upload CA/Sub-CA certificates
	 * 
	 * @param CACertificateRequestDto caCertResponseDto
	 * @return {@link CACertificateResponseDto} instance
	 */
    public CACertificateResponseDto uploadCACertificate(CACertificateRequestDto caCertResponseDto);

    /**
     * Function to Upload Partner certificates
     * 
     * @param PartnerCertificateRequestDto partnerCertResponseDto
     * @return {@link PartnerCertificateResponseDto} instance
    */
    public PartnerCertificateResponseDto uploadPartnerCertificate(PartnerCertificateRequestDto partnerCertResponseDto);

    /**
     * Function to Download Partner certificates
     * 
     * @param PartnerCertDownloadRequestDto certDownloadRequestDto
     * @return {@link PartnerCertDownloadResponeDto} instance
    */
    public PartnerCertDownloadResponeDto getPartnerCertificate(PartnerCertDownloadRequestDto certDownloadRequestDto);

    /**
     * Function to verify partner certificates trust.
     * 
     * @param CertificateTrustRequestDto certificateTrustRequestDto
     * @return {@link CertificateTrustResponeDto} instance
    */
    public CertificateTrustResponeDto verifyCertificateTrust(CertificateTrustRequestDto certificateTrustRequestDto);


    /**
     * Function to Purge trust store cache for the provided partner domain.
     * 
     * @param String partnerDomain
     * @return void 
    */
    public void purgeTrustStoreCache(String partnerDomain);

     /**
     * Function to Download Partner CA Signed certificates & MOSIP CA Signed Certificate.
     * 
     * @param PartnerCertDownloadRequestDto certDownloadRequestDto
     * @return {@link PartnerCertDownloadResponeDto} instance
    */
    public PartnerSignedCertDownloadResponseDto getPartnerSignedCertificate(PartnerCertDownloadRequestDto certDownloadRequestDto);

    /**
     * Function to list the Certificate Based on certificate type.
     *
     * @param CaCertTypeListRequestDto certListRequestDto
     * @return {@link CaCertificateChainResponseDto} response
     */
    public CaCertificateChainResponseDto getCaCertificateChain(CaCertTypeListRequestDto certListRequestDto);
}