package io.mosip.kernel.keymanagerservice.dto;

import io.mosip.kernel.core.keymanager.model.CertificateParameters;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ExtendedCertificateParameters extends CertificateParameters {

    /**
     * List of Subject Alternative Names (SANs) for the certificate
     */
    private List<SanDto> subjectAlternativeNames;

}
