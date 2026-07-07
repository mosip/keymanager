package io.mosip.testrig.apirig.keymanager.testrunner;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import io.mosip.testrig.apirig.testrunner.OTPListener;
import io.mosip.testrig.apirig.utils.*;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.testng.TestNG;

import io.mosip.testrig.apirig.keymanager.utils.KeyManagerConfigManager;
import io.mosip.testrig.apirig.keymanager.utils.KeyManagerUtil;
import io.mosip.testrig.apirig.testrunner.BaseTestCase;
import io.mosip.testrig.apirig.testrunner.ExtractResource;
import io.mosip.testrig.apirig.testrunner.HealthChecker;

/**
 * Entry point for Key Manager API test execution.
 */
public class MosipTestRunner {
	private static final Logger LOGGER = Logger.getLogger(MosipTestRunner.class);
	private static String cachedPath = null;
	private static String generateDependency;

	public static String jarUrl = MosipTestRunner.class.getProtectionDomain().getCodeSource().getLocation().getPath();
	public static List<String> languageList = new ArrayList<>();
	public static boolean skipAll = false;

	public static void main(String[] arg) {
		try {
			LOGGER.info("** ------------- Key Manager API Test Rig Started --------------------------------------------- **");
			setLogLevels();
			BaseTestCase.setRunContext(getRunType(), jarUrl);
			ExtractResource.removeOldMosipTestTestResource();
			if (getRunType().equalsIgnoreCase("JAR")) {
				ExtractResource.extractCommonResourceFromJar();
			} else {
				ExtractResource.copyCommonResources();
			}
			AdminTestUtil.init();
			KeyManagerConfigManager.init();
			suiteSetup(getRunType());
			SkipTestCaseHandler.loadTestcaseToBeSkippedList("testCaseSkippedList.txt");
			GlobalMethods.setModuleNameAndReCompilePattern(KeyManagerConfigManager.getproperty("moduleNamePattern"));
			setLogLevels();

			HealthChecker healthcheck = new HealthChecker();
			healthcheck.setCurrentRunningModule(BaseTestCase.currentModule);
			Thread trigger = new Thread(healthcheck);
			trigger.start();

			KeycloakUserManager.removeUser();
			KeycloakUserManager.createUsers();
			KeycloakUserManager.closeKeycloakInstance();

			generateDependency = KeyManagerConfigManager.getproperty("generateDependencyJson");

			if (!"yes".equalsIgnoreCase(generateDependency)) {
				String testCasesToExecute = KeyManagerConfigManager.getproperty("testCasesToExecute");
				LOGGER.info("Testcases to execute as per config: " + testCasesToExecute);

				if (testCasesToExecute != null && !testCasesToExecute.isBlank()) {
					DependencyResolver.loadDependencies(
							getGlobalResourcePath() + "/config/testCaseInterDependency.json");
					KeyManagerUtil.testCasesInRunScope = DependencyResolver.getDependencies(testCasesToExecute);
				}
			}

			KeyManagerUtil.dbCleanUp();
			KeyManagerUtil.dbSetup();
			startTestRunner();
			KeyManagerUtil.dbCleanUp();

		} catch (Exception e) {
			LOGGER.error("Exception: " + e.getMessage());
		}

		KeycloakUserManager.removeUser();
		KeycloakUserManager.closeKeycloakInstance();

		HealthChecker.bTerminate = true;

		if ("yes".equalsIgnoreCase(generateDependency)) {
			LOGGER.info("Generating test case inter-dependencies");
			AdminTestUtil.generateTestCaseInterDependencies(BaseTestCase.getTestCaseInterDependencyPath());
		}

		System.exit(0);
	}

	public static void suiteSetup(String runType) {
		if (KeyManagerConfigManager.IsDebugEnabled())
			LOGGER.setLevel(Level.ALL);
		else
			LOGGER.info("Key Manager Test Framework Initialized");
		BaseTestCase.initialize();
		LOGGER.info("Done with suite setup — starting test execution\n\n");

		if (!runType.equalsIgnoreCase("JAR")) {
			AuthTestsUtil.removeOldMosipTempTestResource();
		}
		BaseTestCase.currentModule = BaseTestCase.runContext + KeyManagerUtil.MODULE_NAME;
		BaseTestCase.certsForModule = BaseTestCase.runContext + KeyManagerUtil.MODULE_NAME;
		AdminTestUtil.copymoduleSpecificAndConfigFile(KeyManagerUtil.MODULE_NAME);
	}

	private static void setLogLevels() {
		AdminTestUtil.setLogLevel();
		OutputValidationUtil.setLogLevel();
		PartnerRegistration.setLogLevel();
		KeyCloakUserAndAPIKeyGeneration.setLogLevel();
		MispPartnerAndLicenseKeyGeneration.setLogLevel();
		JWKKeyUtil.setLogLevel();
		CertsUtil.setLogLevel();
		KernelAuthentication.setLogLevel();
	}

	public static void startTestRunner() {
		File homeDir = null;
		String os = System.getProperty("os.name");
		LOGGER.info(os);
		if (getRunType().contains("IDE") || os.toLowerCase().contains("windows")) {
			homeDir = new File(System.getProperty("user.dir") + "/testNgXmlFiles");
			LOGGER.info("IDE: " + homeDir);
		} else {
			File dir = new File(System.getProperty("user.dir"));
			homeDir = new File(dir.getParent() + "/mosip/testNgXmlFiles");
			LOGGER.info("JAR: " + homeDir);
		}
		File[] files = homeDir.listFiles();
		if (files != null) {
			for (File file : files) {
				TestNG runner = new TestNG();
				List<String> suitefiles = new ArrayList<>();
				if (file.getName().toLowerCase().contains("mastertestsuite")) {
					BaseTestCase.setReportName(KeyManagerUtil.MODULE_NAME);
					suitefiles.add(file.getAbsolutePath());
					runner.setTestSuites(suitefiles);
					System.getProperties().setProperty("testng.outpur.dir", "testng-report");
					runner.setOutputDirectory("testng-report");
					runner.run();
				}
			}
		} else {
			LOGGER.error("No files found in directory: " + homeDir);
		}
	}

	public static String getGlobalResourcePath() {
		if (cachedPath != null) {
			return cachedPath;
		}
		String path = null;
		if (getRunType().equalsIgnoreCase("JAR")) {
			path = new File(jarUrl).getParentFile().getAbsolutePath()
					+ "/MosipTestResource/MosipTemporaryTestResource";
		} else if (getRunType().equalsIgnoreCase("IDE")) {
			path = new File(MosipTestRunner.class.getClassLoader().getResource("").getPath()).getAbsolutePath()
					+ "/MosipTestResource/MosipTemporaryTestResource";
			if (path.contains(GlobalConstants.TESTCLASSES))
				path = path.replace(GlobalConstants.TESTCLASSES, "classes");
		}
		if (path != null) {
			cachedPath = path;
			return path;
		}
		return "Global Resource File Path Not Found";
	}

	public static String getResourcePath() {
		return getGlobalResourcePath();
	}

	public static Properties getproperty(String path) {
		Properties prop = new Properties();
		FileInputStream inputStream = null;
		try {
			File file = new File(path);
			inputStream = new FileInputStream(file);
			prop.load(inputStream);
		} catch (Exception e) {
			LOGGER.error(GlobalConstants.EXCEPTION_STRING_2 + e.getMessage());
		} finally {
			AdminTestUtil.closeInputStream(inputStream);
		}
		return prop;
	}

	public static String getRunType() {
		if (MosipTestRunner.class.getResource("MosipTestRunner.class").getPath().contains(".jar"))
			return "JAR";
		else
			return "IDE";
	}
}