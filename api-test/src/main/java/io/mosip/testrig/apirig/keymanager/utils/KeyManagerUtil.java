package io.mosip.testrig.apirig.keymanager.utils;

import java.io.StringReader;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.testng.SkipException;

import io.mosip.testrig.apirig.dbaccess.DBManager;
import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.testrunner.BaseTestCase;
import io.mosip.testrig.apirig.utils.AdminTestUtil;
import io.mosip.testrig.apirig.utils.GlobalConstants;
import io.mosip.testrig.apirig.utils.SkipTestCaseHandler;

public class KeyManagerUtil extends AdminTestUtil {

	private static final Logger logger = Logger.getLogger(KeyManagerUtil.class);

	public static final String MODULE_NAME = GlobalConstants.KEYMANAGER;

	public static List<String> testCasesInRunScope = new ArrayList<>();

	public static String isTestCaseValidForExecution(TestCaseDTO testCaseDTO) {
		String testCaseName = testCaseDTO.getTestCaseName();
		currentTestCaseName = testCaseName;

		int indexof = testCaseName.indexOf("_");
		String modifiedTestCaseName = testCaseName.substring(indexof + 1);

		addTestCaseDetailsToMap(modifiedTestCaseName, testCaseDTO.getUniqueIdentifier());

		if (!testCasesInRunScope.isEmpty()
				&& !testCasesInRunScope.contains(testCaseDTO.getUniqueIdentifier())) {
			throw new SkipException(GlobalConstants.NOT_IN_RUN_SCOPE_MESSAGE);
		}

		if (SkipTestCaseHandler.isTestCaseInSkippedList(testCaseName)) {
			throw new SkipException(GlobalConstants.KNOWN_ISSUES);
		}

		if (testCaseDTO.getAdditionalDependencies() != null && AdminTestUtil.generateDependency) {
			addAdditionalDependencies(testCaseDTO);
		}

		return testCaseName;
	}

	public static void dbSetup() {
		DBManager.executeDBQueries(KeyManagerConfigManager.getKMDbUrl(), KeyManagerConfigManager.getKMDbUser(),
				KeyManagerConfigManager.getKMDbPass(), KeyManagerConfigManager.getKMDbSchema(),
				getGlobalResourcePath() + "/" + "config/keyManagerDataQueries.txt");
	}

	public static void dbCleanUp() {
		DBManager.executeDBQueries(KeyManagerConfigManager.getKMDbUrl(), KeyManagerConfigManager.getKMDbUser(),
				KeyManagerConfigManager.getKMDbPass(), KeyManagerConfigManager.getKMDbSchema(),
				getGlobalResourcePath() + "/" + "config/keyManagerDeleteQueries.txt");
	}

	public String augmentResponseWithCsrProperties(String responseJson) {
		try {
			JSONObject json = new JSONObject(responseJson);
			if (!json.has("response") || json.isNull("response"))
				return responseJson;
			JSONObject resp = json.getJSONObject("response");
			if (!resp.has("certSignRequest") || resp.isNull("certSignRequest"))
				return responseJson;

			String csrPem = resp.getString("certSignRequest");
			try (PEMParser parser = new PEMParser(new StringReader(csrPem))) {
				Object obj;
				try {
					obj = parser.readObject();
				} catch (Exception e) {
					logger.warn("CSR parsing failed: " + e.getMessage());
					resp.put("csrIsValid", "false");
					resp.put("csrSignatureValid", "false");
					return json.toString();
				}
				if (!(obj instanceof PKCS10CertificationRequest)) {
					resp.put("csrIsValid", "false");
					resp.put("csrSignatureValid", "false");
					return json.toString();
				}
				PKCS10CertificationRequest csr = (PKCS10CertificationRequest) obj;

				boolean signatureValid = false;
				try {
					ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
							.setProvider(new BouncyCastleProvider()).build(csr.getSubjectPublicKeyInfo());
					signatureValid = csr.isSignatureValid(verifier);
				} catch (Exception e) {
					logger.warn("CSR signature verification failed: " + e.getMessage());
				}

				resp.put("csrIsValid", "true");
				resp.put("csrSignatureValid", signatureValid ? "true" : "false");

				logger.info("CSR augmentation — subject: " + csr.getSubject()
						+ " | signatureValid: " + signatureValid);
			}
			return json.toString();
		} catch (Exception e) {
			logger.warn("augmentResponseWithCsrProperties failed: " + e.getMessage());
			return responseJson;
		}
	}

	public String inputJsonModuleKeyWordHandler(String jsonString, String testCaseName) {
		if (jsonString.contains("$KEYMANAGERAPPID$")) {
			jsonString = jsonString.replace("$KEYMANAGERAPPID$",
					BaseTestCase.runContext.toUpperCase() + "AUTOMATION");
		}
		if (jsonString.contains("$KEYMANAGERCSRAPPID$")) {
			jsonString = jsonString.replace("$KEYMANAGERCSRAPPID$",
					BaseTestCase.runContext.toUpperCase() + "AUTOMATIONCSR");
		}
		return jsonString;
	}

	/**
	 * Decodes the X.509 certificate from {@code response.certificate} in the HTTP
	 * response JSON and injects validation results as extra fields. Returns the
	 * original JSON unchanged when the certificate field is absent or null
	 * (e.g., CSR responses and error responses).
	 */
	public String augmentResponseWithCertProperties(String responseJson) {
		try {
			JSONObject json = new JSONObject(responseJson);
			if (!json.has("response") || json.isNull("response"))
				return responseJson;
			JSONObject resp = json.getJSONObject("response");
			if (!resp.has("certificate") || resp.isNull("certificate"))
				return responseJson;

			String certPem = resp.getString("certificate");
			X509Certificate cert = (X509Certificate) convertToCertificate(certPem);
			if (cert == null) {
				resp.put("certIsValid", "false");
				return json.toString();
			}

			boolean isValid = true;
			try {
				cert.checkValidity();
			} catch (Exception e) {
				isValid = false;
			}

			boolean[] ku = cert.getKeyUsage();
			boolean keyUsageOk = ku != null && (ku[0] || ku[2] || ku[5]);

			resp.put("certIsValid",       isValid    ? "true" : "false");
			resp.put("certKeyUsageValid", keyUsageOk ? "true" : "false");

			logger.info("Cert augmentation — subject: " + cert.getSubjectX500Principal().getName()
					+ " | issuer: " + cert.getIssuerX500Principal().getName()
					+ " | valid: " + isValid + " | keyUsageOk: " + keyUsageOk);

			return json.toString();
		} catch (Exception e) {
			logger.warn("augmentResponseWithCertProperties failed: " + e.getMessage());
			return responseJson;
		}
	}
}