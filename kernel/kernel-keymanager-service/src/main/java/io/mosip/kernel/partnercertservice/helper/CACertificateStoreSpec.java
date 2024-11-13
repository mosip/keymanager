package io.mosip.kernel.partnercertservice.helper;

import io.mosip.kernel.keymanagerservice.entity.CACertificateStore;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class CACertificateStoreSpec {

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
                predicates.add(criteriaBuilder.equal(root.get("certId"), certId));
            }
            if (issuedTo != null) {
                predicates.add(criteriaBuilder.like(root.get("certSubject"), "%" + issuedTo + "%"));
            }
            if (issuedBy != null) {
                predicates.add(criteriaBuilder.like(root.get("certIssuer"), "%" + issuedBy + "%"));
            }
            if (validFrom != null) {
                predicates.add(criteriaBuilder.equal(root.get("certNotBefore"), validFrom));
            }
            if (validTill != null) {
                predicates.add(criteriaBuilder.equal(root.get("certNotAfter"), validTill));
            }
            if (uploadTime != null) {
                predicates.add(criteriaBuilder.equal(root.get("updatedtimes"), uploadTime));
            }
            if(certThumbprints != null && !certThumbprints.isEmpty()) {
                predicates.add(root.get("certThumbprint").in(certThumbprints).not());
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }
}