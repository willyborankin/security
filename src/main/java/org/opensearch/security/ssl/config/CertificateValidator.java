package org.opensearch.security.ssl.config;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@FunctionalInterface
public interface CertificateValidator {

    CertificateValidator DEFAULT_VALIDATOR = X509Certificate::checkValidity;

    void validate(X509Certificate certificate) throws CertificateException;

}
