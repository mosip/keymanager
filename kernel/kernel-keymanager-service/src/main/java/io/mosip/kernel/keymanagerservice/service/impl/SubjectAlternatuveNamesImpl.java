package io.mosip.kernel.keymanagerservice.service.impl;

import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "mosip.kernel.keymanager.certificate")
@Service
public class SubjectAlternatuveNamesImpl {

    /**
     * This map will be populated for all properties like:
     * mosip.kernel.keymanager.certificate.san.<appId>.<refId>=value
     */
    private Map<String, String> sanParameters = new HashMap<>();

    public void setSanParameters(Map<String, String> sanParameters) {
        this.sanParameters = sanParameters;
    }

    public Map<String, String> getSanParameters() {
        return sanParameters;
    }

    public List<SanEntry> getStructuredSanParameters() {
        List<SanEntry> entries = new ArrayList<>();
        for (Map.Entry<String, String> entry : sanParameters.entrySet()) {
            String[] parts = entry.getKey().split("\\.", 2);
            if (parts.length == 2) {
                entries.add(new SanEntry(parts[0], parts[1], entry.getValue()));
            }
        }
        return entries;
    }

    public static class SanEntry {
        private final String appId;
        private final String refId;
        private final String value;

        public SanEntry(String appId, String refId, String value) {
            this.appId = appId;
            this.refId = refId;
            this.value = value;
        }

        public String getAppId() {
            return appId;
        }

        public String getRefId() {
            return refId;
        }

        public String getValue() {
            return value;
        }
    }

    public boolean hasSANappIdAndRefId(String appId, String refId) {
        refId = (refId == null || refId.isEmpty()) ? KeymanagerConstant.STRING_BLANK : refId;
        String key = appId + KeymanagerConstant.DOT + refId;
        return sanParameters.containsKey(key);
    }
}