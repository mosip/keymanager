package io.mosip.kernel.partnercertservice.test.service;

import static org.junit.jupiter.api.Assertions.*;

import java.security.cert.X509Certificate;
import java.util.*;

import io.mosip.kernel.keymanagerservice.constant.KeymanagerErrorConstant;
import io.mosip.kernel.keymanagerservice.entity.CACertificateStore;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.partnercertservice.constant.PartnerCertManagerErrorConstants;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringRunner;

import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.repository.CACertificateStoreRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyStoreRepository;
import io.mosip.kernel.keymanagerservice.repository.PartnerCertificateStoreRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.partnercertservice.dto.*;
import io.mosip.kernel.partnercertservice.exception.PartnerCertManagerException;
import io.mosip.kernel.partnercertservice.service.spi.PartnerCertificateManagerService;

@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class PartnerCertificateManagerServiceTest {

    @Autowired
    private PartnerCertificateManagerService partnerCertService;

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private KeymanagerUtil keymanagerUtil;

    @Autowired
    private CACertificateStoreRepository caCertificateStoreRepository;

    @Autowired
    private PartnerCertificateStoreRepository partnerCertificateStoreRepository;

    @Autowired
    private KeyAliasRepository keyAliasRepository;

    @Autowired
    private KeyStoreRepository keyStoreRepository;

    private String caCertificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDbDCCAlSgAwIBAgIUTW8ScXGEgz/C0o7xnAsBmd3P8hswDQYJKoZIhvcNAQEL\n" +
            "BQAwbzELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5nYWx1\n" +
            "cnUxDjAMBgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXltYW5hZ2VyMRowGAYDVQQD\n" +
            "DBFQTVMtcm9vdC10ZXN0Y2FzZTAgFw0yNTEwMTMxMzQzMzZaGA8yMTI1MTAxMzEz\n" +
            "NDMzNlowbzELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5n\n" +
            "YWx1cnUxDjAMBgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXltYW5hZ2VyMRowGAYD\n" +
            "VQQDDBFQTVMtcm9vdC10ZXN0Y2FzZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n" +
            "AQoCggEBANZqa/+RIVKaoIiQ11pFXOCL1NgOd6F1a98KIWU3ZZ8Kh/CjPN5V5QN/\n" +
            "pqLX5/4+Zw4tJJqsruQmCz76LCLFREuoWTByNtnKZDni1quNRkcz7uiKeOLFHzk4\n" +
            "QODDF4BfefaQElOLSMdHueoKgWBor+/E9aK8+vvk3kPOtC67RmhWCJ5TAI19kCaY\n" +
            "lBrneAx+JmQxJ8sAHszErHxjdlEIUNSoU4GbIrgw4C8dtdG6yVb3arM9+kCsa0hg\n" +
            "JGYCW8igi8P0yyUoeGpi86ZiYjiIVGZS7dmZM/vGun+JjaHtTlBCvCsMxVstrhMZ\n" +
            "AgVZouiaXgmbvubSXDuBBOL6pDRWFocCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA\n" +
            "irKsATgEedB8IoD4WeGW7KRuPxT6iow4yQUf9kODEYzsNKRdvowUD97MnORaF1ns\n" +
            "EtA+vTfutktHHMhnBNfuFyZFsZCqq3skbRGst9RjxokznljE/OZc0q+24Hm9dRfZ\n" +
            "SMBYWPEnFQzpvPmOexLwRRwt6EGrZPWUh22NGYLbJR22CP5wTgsUKwA6MHcAVVTS\n" +
            "5+WcxMD0OMoRX5LIlFLUSyyZb6POs/lsta7+fr2FU84FNLrooz0Q+8/QzTpW/XND\n" +
            "N3yr7o9LBHFXwVB+Fb6ow4/r9hPuBFg58FM+wQt5AJ5cz/LeOKsVpDJ8Bvuodrxa\n" +
            "vb31TtM0csPVLODrpnNZyA==\n" +
            "-----END CERTIFICATE-----";

    private String interCertificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDbTCCAlWgAwIBAgIUVB019PvL2p+YbdMZydcBmd3SydcwDQYJKoZIhvcNAQEL\n" +
            "BQAwbzELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5nYWx1\n" +
            "cnUxDjAMBgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXltYW5hZ2VyMRowGAYDVQQD\n" +
            "DBFQTVMtcm9vdC10ZXN0Y2FzZTAgFw0yNTEwMTMxMzQ2NDNaGA8yMTI0MTAxMzEz\n" +
            "NDY0M1owcDELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5n\n" +
            "YWx1cnUxDjAMBgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXltYW5hZ2VyMRswGQYD\n" +
            "VQQDDBJQTVMtaW50ZXItdGVzdGNhc2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n" +
            "ggEKAoIBAQCVULKkf6haXwl7AQJG1iDWcPy5dNa8wqALEOnwAEGrRcWHgGy+UPEf\n" +
            "8KiwOyOTDMY5ioq4LK5DWCc4RJ0m8JzmhppHq4xQhXkucjLMPgM3+MBljvOQDSlh\n" +
            "u9hgelTF44LP9RPTWePXroTwGHe6Kc9/S93KNh6+MU29TbuW7nY/xEBpf0D58iwF\n" +
            "y3axO3SjEnnRkWaL+v4agYCV8xs92UaLoEw3gGzRb9tDUWEkxyJUyGxzelIV3XgW\n" +
            "+a29QWp2qJRupe4c5yfG+d/cbdDyBvVSxQKQBMGAiCb8Xi3SmDUYgkDgJsRgKUc7\n" +
            "w3xfB3+cyyG75PaA80p8hjsxzY5ZUJh1AgMBAAEwDQYJKoZIhvcNAQELBQADggEB\n" +
            "AJKwswIouSJB3LShLLqPx5b602FlzHmYTG8xIr7aWYjknHDoj6KEod4+wro999Hx\n" +
            "KEERIu79rw0HZtj0uVe+nZK3OJaKcKRhTlzrErrg/niZlvp4E2imMGNug+3npphY\n" +
            "4zhW3sWR2QPv3tNmm+C35jCKY30o5wYwSlOqTdHG/iq6XabYOaLHYjz9fe0ynWFL\n" +
            "0HS8B9fpW7jiz2u/XelIQnjPz8GrS66mjYJzdyx9YKiVi72fFUdtceubihyJSucJ\n" +
            "3XJvNPXeyNuCVCiwv8frI1mkkWyi//I+qxjmbQEkbAP1eLwiirier56MidZa6ZDt\n" +
            "TqOhYcxaaqJaO+XnmrzedjM=\n" +
            "-----END CERTIFICATE-----\n";

    String futureDate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDcjCCAlqgAwIBAgIUeKH9jXJas6Sr5z5NkvsBmevrRdAwDQYJKoZIhvcNAQEL\n" +
            "BQAwazELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5nYWx1\n" +
            "cnUxDjAMBgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXlNYW5hZ2VyMRYwFAYDVQQD\n" +
            "DA10ZXN0Y2FzZS1yb290MCIYDzIxMjAxMDE2MDcyODA4WhgPMjEyNDEwMTYwNzI4\n" +
            "MDhaMHcxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQmVuZ2Fs\n" +
            "dXJ1MQ4wDAYDVQQKDAVNb3NpcDETMBEGA1UECwwKS2V5TWFuYWdlcjEiMCAGA1UE\n" +
            "AwwZdGVzdGNhc2UtaW50ZXItZnV0dXJlZGF0ZTCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
            "ggEPADCCAQoCggEBAJQSsGXVUnLhewrBlDBGLG4h2DoxaEP5AI3Ra8TLiCCo/890\n" +
            "Tml+vJ7af5Uydt5q5X4pZ58B6gm4w8ZKQrMmiQrzW+oZzalUEIH3lZrWEDEbR8sH\n" +
            "fOK4ei1tOdS2asIyHDgBaCHUWIzr5/1zHR2zi00VahkXMYqqY8G793Gm53vrrPN4\n" +
            "9Lze3xtLCrFrcLJQ/EcGXXT23wrVjI7k3CKuhfmbkcPA7/eV71WY+AWH6sezS+px\n" +
            "h3peYMzgMq4sJzFFmAxBRIgeYhRwLuFArnlX/qQRK14FrNkmvnTgGCLT0U99iBzr\n" +
            "srdvadA5gnqEPZhCcet9RatGw6WtKOTcqE1EEdECAwEAATANBgkqhkiG9w0BAQsF\n" +
            "AAOCAQEAeTvOdo+EKz8+EmBO7qv44f4lIxeOIz7035DaA3pq8rDSW/bbNfPQFQTU\n" +
            "gtJGmm0aBbfjyHzQdTf+tAaxmSU1IMZ9s20P/ZP+iMWar+BP97DHPjJg4pTDqoNX\n" +
            "shsBmgEZFx9our2ESS1LPqncf4fW4+rxD8vOWr9x2mAPVUZ4vwxEiWGRCbaPcJe2\n" +
            "fF1IakAyZSBSYoC7VKGkynQ/94Fd4+CyPI4crBTNR8lVCerd1pXbXihyw8nI0+NK\n" +
            "qnGULjo0gmNQysOuNXIHKdMimhkw3Pfm0m6WB8oS+iM6hiLpEkFTRPY0SEG8B7Hy\n" +
            "ryV9sZ644Hmlr+ZpvA6owfMmt09Vow==\n" +
            "-----END CERTIFICATE-----\n";

    String expired = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDazCCAlOgAwIBAgIUQepDAqVFZDoEoQKkB/sBmevs40UwDQYJKoZIhvcNAQEL\n" +
            "BQAwazELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5nYWx1\n" +
            "cnUxDjAMBgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXlNYW5hZ2VyMRYwFAYDVQQD\n" +
            "DA10ZXN0Y2FzZS1yb290MB4XDTE5MTIzMTE4MzAwMFoXDTI0MTIzMTE4MzAwMFow\n" +
            "dDELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5nYWx1cnUx\n" +
            "DjAMBgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXlNYW5hZ2VyMR8wHQYDVQQDDBZ0\n" +
            "ZXN0Y2FzZS1pbnRlci1leHBpcmVkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n" +
            "CgKCAQEAw0ZuOZhumve5A76lSW3682pNsSiNhxH6Wr802otbXIRuuv4U56Q/ilLk\n" +
            "md4mZ5ZRcb9XAdZL7jZschXm17J3sTd4nQsG/2Ej9N4TDYuE2BF1ex+IeldZoUyM\n" +
            "H/w8b6ZY5QYv6YqUPEj2EZWyODkHMx2pVPs38X2I7uYQ3SVQkeFsHFH+FYsxxR4G\n" +
            "VoI067KVGrSnNziV/rthlxO2UbTqQgJ6Q2uI3Mp74sPrbJK3b40xECpo/3EITr5A\n" +
            "y1mbJkFEhjowWHm4gZAnAEgNihME/4uwgsSAI/62oW/UGoi/f3uGrI7bB9nCAM5K\n" +
            "fsZ54VcNFlUzqPj6AWppvurbjkWQ5wIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQB9\n" +
            "fr4OzVF9yTlYcpiK0A8n1tqImxH+dWGrJ/8eGvm4fCc7KGmIbgzHjd1dFBlGibtr\n" +
            "AFFUc+8eHLHRmDzs1FTTC/Th4ffuQJnil6QBbDQcOu4zS6RdOWkVuzu9Ge2fnjKA\n" +
            "75FkRxT7nzlDBhFG3beKuhDZ4F5bcZJrqZa285sA6ddW/niRmPurQ8FxhvTvMtE2\n" +
            "1cy5Lp8q3Azpp2fGy6Ylq43p7nlaLLsBuXJIZZ/ZUwH/o+o6vwKBsuUxhGQ9ftfi\n" +
            "kD5CE6VRByK51N5cP+AsKf1OJmcA0lbaRYzkSeSq4XDovFbQGWbZ/8fZLSpVX/IN\n" +
            "v9p6y7u0KkvHZekOR7ex\n" +
            "-----END CERTIFICATE-----\n";

    String version1= "-----BEGIN CERTIFICATE-----\n" +
            "MIIDaTCCAlECFE+CEhjd/fU0fFTUfD1oAZnsaIziMA0GCSqGSIb3DQEBCwUAMGsx\n" +
            "CzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQmVuZ2FsdXJ1MQ4w\n" +
            "DAYDVQQKDAVNb3NpcDETMBEGA1UECwwKS2V5TWFuYWdlcjEWMBQGA1UEAwwNdGVz\n" +
            "dGNhc2Utcm9vdDAgFw0yNTEwMTYwOTQ0NThaGA8yMTI0MTAxNjA5NDQ1OFowdTEL\n" +
            "MAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5nYWx1cnUxDjAM\n" +
            "BgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXltYW5hZ2VyMSAwHgYDVQQDDBd0ZXN0\n" +
            "Y2FzZS1pbnRlci12ZXJzaW9uMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
            "ggEBANoXEW09SBuT5loaIFs386L5WavykXtoXWLaMDbaajJT4U/KP/0klToKJ3bQ\n" +
            "zNf+O3auXV1aMqWtEhnZpkr4Fo/oHxiDwZRoV4zN949Z9oVxyMv4d2K6/kwPrlD0\n" +
            "VGKylEgHMa5qtw6s8aeRXVOrSxhTvX+z+H4bdIbNxspGObToldTuPxXZtakrEAUr\n" +
            "4sA9rPayzKlexjYyos1ujhT52Adn7pJx6Hq6dfs00PnkUJfn7E8n9/DaJ9+8nSfS\n" +
            "jrAfYcdfJ2lLFR3AqZvxek0y7brmKzoANgWrsHWRIWizAj+tfa7EC5aEdapdDEtK\n" +
            "+AOHeZJSHFuanoxYq4M51s+/0/cCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAhvA3\n" +
            "SU8me2webMl8C4CRo12T4y6FNqxF8eULm9B4/o5VNQHqpFNUnfRT+G/r7kl6IOxV\n" +
            "h7MHrUc2daCM2Pf9VmZe3JPlS6ftBlkUA+jjS7Ntrp7LHeE/lCvSJq7OlQnIZFR4\n" +
            "zZJqXh7pjaK5+ycUc8SIQZkTiGNG7zS03J5yXiZE3py5fU3iXggkdv5CVKyhGEsF\n" +
            "MHELKPU1nli96whnyaLpPkYovy82X2Z35djfVhKKCBV54q+sDovOM1H0MZ3vi/tV\n" +
            "pfI71ptml71vni9GBj9v7DALrNQ264zeWkCbAZ48jiYGzBrbJyflgrJLhpTc4lln\n" +
            "joHWEtAhY15CWHWtwA==\n" +
            "-----END CERTIFICATE-----\n";

    String keysize1024 = "-----BEGIN CERTIFICATE-----\n" +
            "MIIC7TCCAdWgAwIBAgIURvGxMEbA3dZHNb183ogBme0iM5UwDQYJKoZIhvcNAQEL\n" +
            "BQAwazELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5nYWx1\n" +
            "cnUxDjAMBgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXlNYW5hZ2VyMRYwFAYDVQQD\n" +
            "DA10ZXN0Y2FzZS1yb290MCAXDTI1MTAxNjEzMDc0NVoYDzIxMjQxMDE2MTMwNzQ1\n" +
            "WjB4MQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJlbmdhbHVy\n" +
            "dTEOMAwGA1UECgwFTW9zaXAxEzARBgNVBAsMCktleU1hbmFnZXIxIzAhBgNVBAMM\n" +
            "GnRlc3RjYXNlLWludGVyLTEwMjRrZXlzaXplMIGfMA0GCSqGSIb3DQEBAQUAA4GN\n" +
            "ADCBiQKBgQDrYe6adaah89AUsN3Dfb3eMkwvsUkF/8+wpStRzWcoXxWiUTFTNxI1\n" +
            "J0GxoyYhSmb825TA3KqoPp8CR5KI2c9Es8eFQLALjCNSIePdG4NJIKZMz7RXvMzZ\n" +
            "gs1Oq1h/+8V8fS5uHQDsU2AaBh99vchEW/dkTmeTrWsRsdmTzrMHJwIDAQABMA0G\n" +
            "CSqGSIb3DQEBCwUAA4IBAQAjmsKz9MvVgJ7EhtxjkmrW7iC7b6Z/AV55d8rO+ROE\n" +
            "3F2BlsL5SXbi4lImFj1rPAizckwPaNA9sV/3p38ZWxM9SYOyXx8LAJimI8CFk1Eu\n" +
            "nVsnAJoc+uvcotAcPoOAEFbnjOe7nuau7y4Bw7FztZjKkfOYpnugWO1WcafSNnnH\n" +
            "UTI6+8bzspEmH0G51SMZ+qngPQ+RZNQZrzFwimx7igaWGfyVmB8Rmy4IQ9LGoOCp\n" +
            "ybrzsObmrahgvxWqudAFG8FqckI9PDSxDfl6G2ov4ASnlcDAve2iTO6iIhmsylJg\n" +
            "YiMbFzk+Xn7+RZtNBnBe/zsP+1FLEEZTIvy2nfEhWeEk\n" +
            "-----END CERTIFICATE-----\n";

    @Before
    public void setUp() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ROOT");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
    }

    @After
    public void tearDown() {
        partnerCertificateStoreRepository.deleteAll();
        caCertificateStoreRepository.deleteAll();
        keyStoreRepository.deleteAll();
        keyAliasRepository.deleteAll();
    }

    @Test
    public void testUploadCACertificate_Success() {
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(caCertificate);
        requestDto.setPartnerDomain("FTM");

        CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);

        Assert.assertNotNull(response);
        Assert.assertEquals("Upload Success.", response.getStatus());
        Assert.assertNotNull(response.getTimestamp());

        requestDto.setCertificateData(interCertificate);
        response = partnerCertService.uploadCACertificate(requestDto);
        Assert.assertEquals("Upload Success.", response.getStatus());
    }

    @Test
    public void testUploadCACertificate_InvalidCertificate() {
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData("invalid-certificate-data");
        requestDto.setPartnerDomain("FTM");

        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadCACertificate(requestDto);
        });

        Assert.assertEquals("KER-PCM-001", exception.getErrorCode());
    }

    @Test
    public void testUploadCACertificate_InvalidPartnerDomain() {
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(caCertificate);
        requestDto.setPartnerDomain("INVALID_DOMAIN");

        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadCACertificate(requestDto);
        });

        Assert.assertEquals("KER-PCM-011", exception.getErrorCode());
    }

    @Test
    public void testUploadCACertificate_DuplicateCertificate() {
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(caCertificate);
        requestDto.setPartnerDomain("FTM");

        // Upload first time
        partnerCertService.uploadCACertificate(requestDto);

        // Try to upload same certificate again
        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadCACertificate(requestDto);
        });

        Assert.assertEquals("KER-PCM-003", exception.getErrorCode());
    }

    @Test
    public void testUploadPartnerCertificate_Success() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        // First upload CA certificate
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        // Now upload partner certificate
        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData(interCertificate);
        requestDto.setOrganizationName("Mosip");
        requestDto.setPartnerDomain("FTM");

        PartnerCertificateResponseDto response = partnerCertService.uploadPartnerCertificate(requestDto);

        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getCertificateId());
        Assert.assertNotNull(response.getSignedCertificateData());
        Assert.assertNotNull(response.getTimestamp());
    }

    @Test
    public void testUploadPartnerCertificate_InvalidCertificate() {
        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData("invalid-certificate-data");
        requestDto.setOrganizationName("MOSIP");
        requestDto.setPartnerDomain("FTM");

        KeymanagerServiceException exception = assertThrows(KeymanagerServiceException.class, () -> {
            partnerCertService.uploadPartnerCertificate(requestDto);
        });

        Assert.assertEquals("KER-KMS-013", exception.getErrorCode());
    }

    @Test
    public void testUploadPartnerCertificate_NoRootCA() {
        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData(interCertificate);
        requestDto.setOrganizationName("MOSIP");
        requestDto.setPartnerDomain("FTM");

        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadPartnerCertificate(requestDto);
        });

        Assert.assertEquals("KER-PCM-006", exception.getErrorCode());
    }

    @Test
    public void testGetPartnerCertificate_Success() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        PartnerCertificateRequestDto partnerCertRequestDto = new PartnerCertificateRequestDto();
        partnerCertRequestDto.setCertificateData(interCertificate);
        partnerCertRequestDto.setOrganizationName("Mosip");
        partnerCertRequestDto.setPartnerDomain("FTM");
        PartnerCertificateResponseDto uploadResponse = partnerCertService.uploadPartnerCertificate(partnerCertRequestDto);

        // Now get the certificate
        PartnerCertDownloadRequestDto downloadRequestDto = new PartnerCertDownloadRequestDto();
        downloadRequestDto.setPartnerCertId(uploadResponse.getCertificateId());

        PartnerCertDownloadResponeDto response = partnerCertService.getPartnerCertificate(downloadRequestDto);

        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getCertificateData());
        Assert.assertNotNull(response.getTimestamp());
    }

    @Test(expected = PartnerCertManagerException.class)
    public void testGetPartnerCertificateException() {
        PartnerCertDownloadRequestDto downloadRequestDto = new PartnerCertDownloadRequestDto();
        downloadRequestDto.setPartnerCertId("invalid-cert-id");
        partnerCertService.getPartnerCertificate(downloadRequestDto);
    }

    @Test
    public void testVerifyCertificateTrust_Success() {
        // First upload CA certificate
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        // Verify certificate trust
        CertificateTrustRequestDto requestDto = new CertificateTrustRequestDto();
        requestDto.setCertificateData(interCertificate);
        requestDto.setPartnerDomain("FTM");

        CertificateTrustResponeDto response = partnerCertService.verifyCertificateTrust(requestDto);

        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getStatus());
    }

    @Test
    public void testVerifyCertificateTrust_InvalidCertificate() {
        CertificateTrustRequestDto requestDto = new CertificateTrustRequestDto();
        requestDto.setCertificateData("invalid-certificate-data");
        requestDto.setPartnerDomain("FTM");

        KeymanagerServiceException exception = assertThrows(KeymanagerServiceException.class, () -> {
            partnerCertService.verifyCertificateTrust(requestDto);
        });

        Assert.assertEquals("KER-KMS-013", exception.getErrorCode());

        requestDto.setCertificateData("");
        PartnerCertManagerException exception2 = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.verifyCertificateTrust(requestDto);
        });

        Assert.assertEquals("KER-PCM-001", exception2.getErrorCode());
    }

    @Test
    public void testUploadCACertificate_MultiplePartnerDomains() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();
        String[] domains = {"FTM", "DEVICE", "AUTH"};

        for (String domain : domains) {
            CACertificateRequestDto requestDto = new CACertificateRequestDto();
            requestDto.setCertificateData(validCACertData);
            requestDto.setPartnerDomain(domain);

            CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);
            Assert.assertEquals("Upload Success.", response.getStatus());
        }
    }

    @Test
    public void testUploadPartnerCertificate_MultiplePartnerDomains() {
        String[] domains = {"FTM", "DEVICE", "AUTH"};

        for (String domain : domains) {
            // Upload CA certificate first
            CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
            caCertRequestDto.setCertificateData(caCertificate);
            caCertRequestDto.setPartnerDomain(domain);
            partnerCertService.uploadCACertificate(caCertRequestDto);

            // Upload partner certificate
            PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
            requestDto.setCertificateData(interCertificate);
            requestDto.setOrganizationName("Mosip");
            requestDto.setPartnerDomain(domain);

            PartnerCertificateResponseDto response = partnerCertService.uploadPartnerCertificate(requestDto);
            Assert.assertNotNull(response.getCertificateId());
        }
    }

    @Test
    public void testUploadCACertificate_FutureDatedCertificate() {
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(caCertificate);
        requestDto.setPartnerDomain("FTM");

        CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);
        Assert.assertEquals("Upload Success.", response.getStatus());
    }

    @Test
    public void testUploadPartnerCertificate_OrganizationMismatch() {
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        // Try to upload partner certificate with wrong organization
        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData(interCertificate);
        requestDto.setOrganizationName("WRONG_ORG");
        requestDto.setPartnerDomain("FTM");

        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadPartnerCertificate(requestDto);
        });

        Assert.assertEquals("KER-PCM-008", exception.getErrorCode());
    }

    @Test
    public void testGetPartnerCertificate_InvalidCertificateId() {
        PartnerCertDownloadRequestDto requestDto = new PartnerCertDownloadRequestDto();
        requestDto.setPartnerCertId("invalid-cert-id");

        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.getPartnerCertificate(requestDto);
        });

        Assert.assertEquals("KER-PCM-012", exception.getErrorCode());
    }

    @Test
    public void testVerifyCertificateTrust_NoTrustPath() {
        CertificateTrustRequestDto requestDto = new CertificateTrustRequestDto();
        requestDto.setCertificateData(interCertificate);
        requestDto.setPartnerDomain("FTM");

        CertificateTrustResponeDto response = partnerCertService.verifyCertificateTrust(requestDto);

        Assert.assertNotNull(response);
        Assert.assertFalse(response.getStatus());
    }

    @Test
    public void testUploadCACertificate_P7BFormat() {
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setPartnerDomain("FTM");
        requestDto.setCertificateData(caCertificate);

        CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);
        Assert.assertEquals("Upload Success.", response.getStatus());
    }

    @Test
    public void testUploadCACertificate_ExpiredCertificate() {
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(caCertificate);
        requestDto.setPartnerDomain("FTM");

        // Current certificate should be valid
        CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);
        Assert.assertEquals("Upload Success.", response.getStatus());
    }

    @Test
    public void testCertificateValidation_AllDomains() {
        String[] validDomains = {"FTM", "DEVICE", "AUTH"};

        for (String domain : validDomains) {
            CACertificateRequestDto requestDto = new CACertificateRequestDto();
            requestDto.setCertificateData(caCertificate);
            requestDto.setPartnerDomain(domain);

            CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);
            Assert.assertEquals("Upload Success.", response.getStatus());
            partnerCertService.purgeTrustStoreCache(domain);
        }
    }

    @Test
    public void testGetPartnerSignedCertificate(){
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        PartnerCertificateRequestDto partnerCertRequestDto = new PartnerCertificateRequestDto();
        partnerCertRequestDto.setCertificateData(interCertificate);
        partnerCertRequestDto.setOrganizationName("Mosip");
        partnerCertRequestDto.setPartnerDomain("FTM");
        PartnerCertificateResponseDto uploadResponse = partnerCertService.uploadPartnerCertificate(partnerCertRequestDto);

        // Now get the certificate
        PartnerCertDownloadRequestDto downloadRequestDto = new PartnerCertDownloadRequestDto();
        downloadRequestDto.setPartnerCertId(uploadResponse.getCertificateId());
        PartnerCertDownloadResponeDto response = partnerCertService.getPartnerCertificate(downloadRequestDto);

        Assert.assertNotNull(response.getCertificateData());
    }

    @Test
    public void testGetCACertificateTrustPath() {
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        caCertRequestDto.setCertificateData(interCertificate);
        partnerCertService.uploadCACertificate(caCertRequestDto);
        // Now get the certificate
        CACertificateStore caCertListLast = caCertificateStoreRepository.findAll().getLast();
        CACertificateTrustPathRequestDto caCertificateTrustPathRequestDto = new CACertificateTrustPathRequestDto();
        caCertificateTrustPathRequestDto.setCaCertId(caCertListLast.getCertId());

        CACertificateTrustPathResponseDto responseDto = partnerCertService.getCACertificateTrustPath(caCertificateTrustPathRequestDto);
        Assert.assertNotNull(responseDto);

        CACertificateStore caCertListFirst = caCertificateStoreRepository.findAll().getFirst();
        caCertificateTrustPathRequestDto.setCaCertId(caCertListFirst.getCertId());

        responseDto = partnerCertService.getCACertificateTrustPath(caCertificateTrustPathRequestDto);
        Assert.assertNotNull(responseDto);
    }

    @Test(expected = PartnerCertManagerException.class)
    public void testGetCACertificatePMSException() {
        CACertificateTrustPathRequestDto caCertificateTrustPathRequestDto = new CACertificateTrustPathRequestDto();
        caCertificateTrustPathRequestDto.setCaCertId("");
        partnerCertService.getCACertificateTrustPath(caCertificateTrustPathRequestDto);

        caCertificateTrustPathRequestDto.setCaCertId("invalid-cert-id");
        partnerCertService.getCACertificateTrustPath(caCertificateTrustPathRequestDto);
    }

    @Test
    public void testGetCACertificateChain() {
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        caCertRequestDto.setCertificateData(interCertificate);
        partnerCertService.uploadCACertificate(caCertRequestDto);

        CaCertTypeListRequestDto certListRequestDto = new CaCertTypeListRequestDto();
        certListRequestDto.setPartnerDomain("FTM");
        certListRequestDto.setCaCertificateType("ROOT");
        certListRequestDto.setExcludeMosipCA(false);
        certListRequestDto.setSortByFieldName("certId");
        certListRequestDto.setSortOrder("asc");

        CaCertificateChainResponseDto responseDto = partnerCertService.getCaCertificateChain(certListRequestDto);
        Assert.assertNotNull(responseDto);
    }

    @Test
    public void testValidateCertPathWithInterCertTrust() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        PartnerCertificateRequestDto partnerCertRequestDto = new PartnerCertificateRequestDto();
        partnerCertRequestDto.setCertificateData(interCertificate);
        partnerCertRequestDto.setOrganizationName("Mosip");
        partnerCertRequestDto.setPartnerDomain("FTM");
        PartnerCertificateResponseDto uploadResponse = partnerCertService.uploadPartnerCertificate(partnerCertRequestDto);

        PartnerCertDownloadRequestDto downloadRequestDto = new PartnerCertDownloadRequestDto();
        downloadRequestDto.setPartnerCertId(uploadResponse.getCertificateId());
        PartnerCertDownloadResponeDto partnerCert = partnerCertService.getPartnerCertificate(downloadRequestDto);
        X509Certificate x509Certificate = (X509Certificate) keymanagerUtil.convertToCertificate(partnerCert.getCertificateData());
        Set<X509Certificate> interCert = new HashSet<>(Collections.singleton(x509Certificate));

        boolean result = partnerCertService.validateCertificatePathWithInterCertTrust(x509Certificate, "FTM", interCert);
        Assert.assertFalse(result);
    }

    @Test
    public void testUploadCACertificateException() {
        String subCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDZTCCAk2gAwIBAgIUbCpYpcvH874bXFjbnO4BmeuYJxYwDQYJKoZIhvcNAQEL\n" +
                "BQAwazELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5nYWx1\n" +
                "cnUxDjAMBgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXlNYW5hZ2VyMRYwFAYDVQQD\n" +
                "DA10ZXN0Y2FzZS1yb290MCAXDTI1MTAxNjA1NTcyMVoYDzIxMjQxMDE2MDU1NzIx\n" +
                "WjBsMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJlbmdhbHVy\n" +
                "dTEOMAwGA1UECgwFTW9zaXAxEzARBgNVBAsMCktleU1hbmFnZXIxFzAVBgNVBAMM\n" +
                "DnRlc3RjYXNlLWludGVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n" +
                "oK6rk5p61d+lo8cJQtlH6tiS2Lq7V9TRsLuRqBweAI1SKqSxoxVI0P0uGcb/3bVw\n" +
                "LNEp1agPzVLrGM4bUsr+PkFOx3XeKrcCU7U92/lS+7ao0XCyzDXYT4sJ+jS/ctnP\n" +
                "EA9djd7UCiefvsrsXXoxyIww7Sh3A+d2z1ug9/594J9dr2UCEsQ139EBN4CcEKP/\n" +
                "U6i0Bna6z8WyK99Zs6mqFXd80igna6dScEFMtO4zgOP9tiKaKz7S88Sx5EXIlv2Y\n" +
                "W8Dfagjq5Cy9fGCevJkrMoEDquo9zZ7ZmtnJghN9X7EKUj9RVviqqMo/zga2fAxT\n" +
                "ZsEpt/3/r2G3Nv7B2AX38QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAKEH5M3TEB\n" +
                "w0oiWaCZfhQMVC+ccMmFg1uGaUadcUVVMmfV9xHSgMnq4ryUiDLAGzDIqDhvW62u\n" +
                "QPJ1qbyp43P34NhLVmVPjoOLoR+pIXf8yldhweIhfRTOnj24iF5kDD+AOITmh9au\n" +
                "43db+FndcoJ8vjiG41YH1083CMmJMkcuXbtCaRKM375m1/5tjypn/LeqqDFHE0eK\n" +
                "kLibISFG5fy9HwylJ0nFIlccuaq2itARFUMmC1CvFWaFiPXKZCpaafmo0giYadLQ\n" +
                "U311e4+r9fDDsvQK4AccDwWRR/jbe/h4bXIXwjFXR5e3GulNx8LYknb7k8HWcZ10\n" +
                "sgTjTfGOc679\n" +
                "-----END CERTIFICATE-----\n";

        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData("");
        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadCACertificate(requestDto);
        });

        Assert.assertEquals(PartnerCertManagerErrorConstants.INVALID_CERTIFICATE.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-PCM-001 --> Invalid Certificate uploaded.", exception.getMessage());

        requestDto.setCertificateData(subCACert);
        requestDto.setPartnerDomain("AUTH");
        exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadCACertificate(requestDto);
        });
        Assert.assertEquals(PartnerCertManagerErrorConstants.ROOT_CA_NOT_FOUND.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-PCM-005 --> Root CA Certificate not found.", exception.getMessage());

        requestDto.setCertificateData("qwertyuiopasdf}ghjklzxcvbn{m/ajp|nkjxaxaaxansxba");
        requestDto.setPartnerDomain("AUTH");
        exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadCACertificate(requestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.CERTIFICATE_PARSING_ERROR.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-013 --> Certificate Parsing Error.", exception.getMessage());
    }

    @Test
    public void testValidateBasicPartnerCertParams() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        CACertificateRequestDto caCerRequestDto = new CACertificateRequestDto();
        caCerRequestDto.setCertificateData(caCertificate);
        caCerRequestDto.setPartnerDomain("DEVICE");
        partnerCertService.uploadCACertificate(caCerRequestDto);

        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData("");
        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadPartnerCertificate(requestDto);
        });
        Assert.assertEquals(PartnerCertManagerErrorConstants.INVALID_CERTIFICATE.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-PCM-001 --> Invalid Certificate uploaded.", exception.getMessage());

        requestDto.setCertificateData(interCertificate);
        requestDto.setOrganizationName("Mosip");
        requestDto.setPartnerDomain("DEVICE");
        partnerCertService.uploadPartnerCertificate(requestDto);
        partnerCertService.uploadPartnerCertificate(requestDto);

        requestDto.setCertificateData(futureDate);
        requestDto.setOrganizationName("Mosip");
        requestDto.setPartnerDomain("DEVICE");
        exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadPartnerCertificate(requestDto);
        });
        Assert.assertEquals(PartnerCertManagerErrorConstants.FUTURE_DATED_CERT_NOT_ALLOWED.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-PMS-020 --> Future Dated Certificate not allowed to upload.", exception.getMessage());

        requestDto.setCertificateData(expired);
        exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadPartnerCertificate(requestDto);
        });
        Assert.assertEquals(PartnerCertManagerErrorConstants.CERTIFICATE_DATES_NOT_VALID.getErrorCode(), exception.getErrorCode());

        requestDto.setCertificateData(caCertificate);
        exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadPartnerCertificate(requestDto);
        });
        Assert.assertEquals(PartnerCertManagerErrorConstants.SELF_SIGNED_CERT_NOT_ALLOWED.getErrorCode(), exception.getErrorCode());
    }

    @Test
    public void testValidateBasicCaCertParams() {
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(caCertificate);
        requestDto.setPartnerDomain("AUTH");
        partnerCertService.uploadCACertificate(requestDto);

        requestDto.setCertificateData(futureDate);
        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadCACertificate(requestDto);
        });
        Assert.assertEquals(PartnerCertManagerErrorConstants.FUTURE_DATED_CERT_NOT_ALLOWED.getErrorCode(), exception.getErrorCode());

        requestDto.setCertificateData(expired);
        exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadCACertificate(requestDto);
        });
        Assert.assertEquals(PartnerCertManagerErrorConstants.CERTIFICATE_DATES_NOT_VALID.getErrorCode(), exception.getErrorCode());

        requestDto.setCertificateData(version1);
        exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadCACertificate(requestDto);
        });
        Assert.assertEquals(PartnerCertManagerErrorConstants.INVALID_CERT_VERSION.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-PCM-007 --> Certificate version not supported.", exception.getMessage());
    }

    @Test
    public void testValidateOtherPartnerCertParams() {
        String newCa = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDZDCCAkygAwIBAgIUT9keAt/Eb2aS/7U2zdMBmeuWUiswDQYJKoZIhvcNAQEL\n" +
                "BQAwazELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5nYWx1\n" +
                "cnUxDjAMBgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXlNYW5hZ2VyMRYwFAYDVQQD\n" +
                "DA10ZXN0Y2FzZS1yb290MCAXDTI1MTAxNjA1NTUyMVoYDzIxMjUxMDE2MDU1NTIx\n" +
                "WjBrMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJlbmdhbHVy\n" +
                "dTEOMAwGA1UECgwFTW9zaXAxEzARBgNVBAsMCktleU1hbmFnZXIxFjAUBgNVBAMM\n" +
                "DXRlc3RjYXNlLXJvb3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCv\n" +
                "CNYSufFlOQccVEeK+Y4lNxd6tS9YfKH14oQOIEeMzRmB3/iIWb/Pe4BdN+i55lq3\n" +
                "Fsj4CAfdb21mtdVQXdjNtsDmOOW3VsGhFD7J6A12W5CFjmrMFJ2OrmaDjb+whudy\n" +
                "vXSFLpNVeReJZR25G8wDZ4IVlv+IjH322XqUwCf6jVU2e0MIHxmUytEKcty1lviD\n" +
                "Y3t0gN6hxL05QhUNs9l902gITWgIjI+nLW/XJUX+/ccpaiSufj3z35I8fjJF+5ur\n" +
                "UED9jPfCbtwjE2cQ4GrQOg2QOr7eMJlS/F7P2NrZfTQQZnznkKh6tdmFhRSzI+k+\n" +
                "W2dyI6hpQRXuD+bn8aCHAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHNmxEQabs3W\n" +
                "9axA3lp3Otp23Y+GWIWJsXkezVAfkx+pra0mvLQuzxKFBwrIbdVa7mT+BK+4uuD5\n" +
                "rYIKzzIUWTcYgPQ3KJpzTB/Af4+wFytbmD4AFahnvwtDIHNipLuh9nnVcnboL1Y0\n" +
                "/uII97Oyr3rp/qfKsmDAIxb6tbbPVQr8AoXdywT/rde0nfwYK7YVmbzTXewG9COe\n" +
                "zoX5IGjhpmI7qUsU73bVp4Wy6tVW8J42iyyKJu8edFr4GiArFChQtQUydyePg418\n" +
                "dhAfPzih8XxAK1YeplMIjO+Abvgh+PgyN+KgwTXhi+eYwFdyw34/duVWT97NYTUW\n" +
                "I+Zf9mSoUYQ=\n" +
                "-----END CERTIFICATE-----\n";

        CACertificateRequestDto caCerRequestDto = new CACertificateRequestDto();
        caCerRequestDto.setCertificateData(caCertificate);
        caCerRequestDto.setPartnerDomain("DEVICE");
        partnerCertService.uploadCACertificate(caCerRequestDto);

        caCerRequestDto.setCertificateData(newCa);
        partnerCertService.uploadCACertificate(caCerRequestDto);

        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData(version1);
        requestDto.setPartnerDomain("DEVICE");

        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadPartnerCertificate(requestDto);
        });
        Assert.assertEquals(PartnerCertManagerErrorConstants.INVALID_CERT_VERSION.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-PCM-007 --> Certificate version not supported.", exception.getMessage());

        requestDto.setCertificateData(interCertificate);
        requestDto.setOrganizationName("CyberPWN");

        exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadPartnerCertificate(requestDto);
        });
        Assert.assertEquals(PartnerCertManagerErrorConstants.PARTNER_ORG_NOT_MATCH.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-PCM-008 --> Partner Organization Name not Matched.", exception.getMessage());

        requestDto.setCertificateData(keysize1024);
        requestDto.setOrganizationName("Mosip");
        exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadPartnerCertificate(requestDto);
        });
        Assert.assertEquals(PartnerCertManagerErrorConstants.CERT_KEY_NOT_ALLOWED.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-PCM-013 --> Partner Certificate Key Size is less than allowed size.", exception.getMessage());
    }

    @Test(expected = PartnerCertManagerException.class)
    public void testGetCACertificateException() {
        CACertificateTrustPathRequestDto requestDto = new CACertificateTrustPathRequestDto();
        requestDto.setCaCertId("invalidCertID");
        partnerCertService.getCACertificateTrustPath(requestDto);
    }

    @Test(expected = PartnerCertManagerException.class)
    public void testGetPartnerCertificatePIDException() {
        PartnerCertDownloadRequestDto requestDto = new PartnerCertDownloadRequestDto();
        requestDto.setPartnerCertId("");
        partnerCertService.getPartnerCertificate(requestDto);
    }

    @Test
    public void testGetCACertificatesException() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("DEVICE");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        caCertRequestDto.setCertificateData(interCertificate);
        partnerCertService.uploadCACertificate(caCertRequestDto);

        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData(interCertificate);
        requestDto.setPartnerDomain("DEVICE");
        requestDto.setOrganizationName("Mosip");
        PartnerCertificateResponseDto responeDto = partnerCertService.uploadPartnerCertificate(requestDto);

        CaCertTypeListRequestDto certListRequestDto = new CaCertTypeListRequestDto();

        CaCertificateChainResponseDto responseDto = partnerCertService.getCaCertificateChain(certListRequestDto);
        Assert.assertNotNull(responeDto);
        certListRequestDto.setPartnerDomain("DEVICE");
        certListRequestDto.setCaCertificateType("INTERMEDIATE");
        certListRequestDto.setExcludeMosipCA(false);
        certListRequestDto.setSortByFieldName("certId");
        certListRequestDto.setSortOrder("asc");
        certListRequestDto.setCertId(responeDto.getCertificateId());
        certListRequestDto.setIssuedTo("Mosip");
        certListRequestDto.setIssuedBy("Mosip");
        certListRequestDto.setValidFromDate(responeDto.getTimestamp());
        certListRequestDto.setValidFromDate(responeDto.getTimestamp().plusYears(10));
        certListRequestDto.setUploadTime(responeDto.getTimestamp().plusYears(5));

        responseDto = partnerCertService.getCaCertificateChain(certListRequestDto);
        Assert.assertNotNull(responseDto);
    }
}