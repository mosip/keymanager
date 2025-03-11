package io.mosip.kernel.partnercertservice.helper;

import io.mosip.kernel.keymanagerservice.entity.CACertificateStore;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class CACertificateStoreSpec {

    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    public static Specification<CACertificateStore> filterCertificates(
            String caCertificateType,
            String partnerDomain,
            String certId,
            String issuedTo,
            String issuedBy,
            LocalDateTime validFrom,
            LocalDateTime validTill,
            LocalDateTime uploadTime,
            List<String> certThumbprints) {

        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (caCertificateType != null) {
                predicates.add(criteriaBuilder.equal(root.get("caCertificateType"), caCertificateType));
            }
            if (partnerDomain != null) {
                predicates.add(criteriaBuilder.equal(root.get("partnerDomain"), partnerDomain));
            }
            if (certId != null) {
                predicates.add(criteriaBuilder.like(criteriaBuilder.lower(root.get("certId")), "%" + certId.toLowerCase() + "%"));
            }
            if (issuedTo != null) {
                predicates.add(criteriaBuilder.like(criteriaBuilder.lower(root.get("certSubject")), "%" + issuedTo.toLowerCase() + "%"));
            }
            if (issuedBy != null) {
                predicates.add(criteriaBuilder.like(criteriaBuilder.lower(root.get("certIssuer")), "%" + issuedBy.toLowerCase() + "%"));
            }
            if (validFrom != null) {
                predicates.add(criteriaBuilder.like(
                        criteriaBuilder.toString(root.get("certNotBefore")),
                        "%" + validFrom.format(DATE_TIME_FORMATTER) + "%"));
            }
            if (validTill != null) {
                predicates.add(criteriaBuilder.like(
                        criteriaBuilder.toString(root.get("certNotAfter")),
                        "%" + validTill.format(DATE_TIME_FORMATTER) + "%"));
            }
            if (uploadTime != null) {
                predicates.add(criteriaBuilder.like(
                        criteriaBuilder.toString(root.get("updatedtimes")),
                        "%" + uploadTime.format(DATE_TIME_FORMATTER) + "%"));
            }
            if(certThumbprints != null && !certThumbprints.isEmpty()) {
                predicates.add(root.get("certThumbprint").in(certThumbprints).not());
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }
}