package io.mosip.kernel.keymanagerservice.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SubjectAlternativeNamesDto {
    /**
     * Type of SAN entry (e.g., DNS, IP, URI, etc.)
     */
    private String type;

    /**
     * Value of the given SAN type
     */
    private String value;
}
