/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.dlic.rest.api;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.ssl.SecurityKeyStore;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.opensearch.security.dlic.rest.api.Responses.badRequest;
import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * Rest API action to get SSL certificate information related to http and transport encryption.
 * Only super admin users are allowed to access this API.
 * This action serves GET request for _plugins/_security/api/ssl/certs endpoint and
 * PUT _plugins/_security/api/ssl/{certType}/reloadcerts
 */
public class SecuritySSLCertsAction extends AbstractApiAction {
    private static final List<Route> ROUTES = addRoutesPrefix(
        ImmutableList.of(new Route(Method.GET, "/ssl/certs"), new Route(Method.PUT, "/ssl/{certType}/reloadcerts/"))
    );

    private final SecurityKeyStore securityKeyStore;

    private final boolean certificatesReloadEnabled;

    private final boolean httpsEnabled;

    public SecuritySSLCertsAction(
        final Settings settings,
        final Path configPath,
        final RestController controller,
        final Client client,
        final AdminDNs adminDNs,
        final ConfigurationRepository cl,
        final ClusterService cs,
        final PrincipalExtractor principalExtractor,
        final PrivilegesEvaluator privilegesEvaluator,
        final ThreadPool threadPool,
        final AuditLog auditLog,
        final SecurityKeyStore securityKeyStore,
        final boolean certificatesReloadEnabled
    ) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, privilegesEvaluator, threadPool, auditLog);
        this.securityKeyStore = securityKeyStore;
        this.certificatesReloadEnabled = certificatesReloadEnabled;
        this.httpsEnabled = settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true);
        this.requestHandlersBuilder.configureRequestHandlers(this::securitySSLCertsRequestHandlers);
    }

    @Override
    protected boolean hasPermissionsToCreate(
        final SecurityDynamicConfiguration<?> dynamicConfigFactory,
        final Object content,
        final String resourceName
    ) {
        return true;
    }

    @Override
    public List<Route> routes() {
        return ROUTES;
    }

    private void securitySSLCertsRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        // spotless:off
        requestHandlersBuilder.withAccessHandler(this::accessHandler)
            .allMethodsNotImplemented()
            .verifyAccessForAllMethods()
            .override(Method.GET, (channel, request, client) ->
                    withSecurityKeyStore()
                            .valid(keyStore -> loadCertificates(channel, keyStore))
                            .error((status, toXContent) -> Responses.response(channel, status, toXContent)))
            .override(Method.PUT, (channel, request, client) -> withSecurityKeyStore().valid(keyStore -> {
                if (!certificatesReloadEnabled) {
                    badRequest(
                        channel,
                        String.format(
                            "no handler found for uri [%s] and method [%s]. In order to use SSL reload functionality set %s to true",
                            request.path(),
                            request.method(),
                            ConfigConstants.SECURITY_SSL_CERT_RELOAD_ENABLED
                        )
                    );
                } else {
                    reloadCertificates(channel, request, keyStore);
                }
            }).error((status, toXContent) -> Responses.response(channel, status, toXContent)));
        // spotless:on
    }

    private boolean accessHandler(final RestRequest request) {
        switch (request.method()) {
            case GET:
                return restApiAdminPrivilegesEvaluator.isCurrentUserRestApiAdminFor(getEndpoint(), "certs");
            case PUT:
                return restApiAdminPrivilegesEvaluator.isCurrentUserRestApiAdminFor(getEndpoint(), "reloadcerts");
            default:
                return false;
        }
    }

    private ValidationResult<SecurityKeyStore> withSecurityKeyStore() {
        if (securityKeyStore == null) {
            return ValidationResult.error(RestStatus.OK, badRequestMessage("keystore is not initialized"));
        }
        return ValidationResult.success(securityKeyStore);
    }

    protected void loadCertificates(final RestChannel channel, final SecurityKeyStore keyStore) throws IOException {
        ok(
            channel,
            (builder, params) -> builder.startObject()
                .field("http_certificates_list", httpsEnabled ? generateCertDetailList(keyStore.getHttpCerts()) : null)
                .field("transport_certificates_list", generateCertDetailList(keyStore.getTransportCerts()))
                .endObject()
        );
    }

    private List<Map<String, String>> generateCertDetailList(final X509Certificate[] certs) {
        if (certs == null) {
            return null;
        }
        return Arrays.stream(certs).map(cert -> {
            final String issuerDn = cert != null && cert.getIssuerX500Principal() != null ? cert.getIssuerX500Principal().getName() : "";
            final String subjectDn = cert != null && cert.getSubjectX500Principal() != null ? cert.getSubjectX500Principal().getName() : "";

            final String san = securityKeyStore.getSubjectAlternativeNames(cert);

            final String notBefore = cert != null && cert.getNotBefore() != null ? cert.getNotBefore().toInstant().toString() : "";
            final String notAfter = cert != null && cert.getNotAfter() != null ? cert.getNotAfter().toInstant().toString() : "";
            return ImmutableMap.of(
                "issuer_dn",
                issuerDn,
                "subject_dn",
                subjectDn,
                "san",
                san,
                "not_before",
                notBefore,
                "not_after",
                notAfter
            );
        }).collect(Collectors.toList());
    }

    protected void reloadCertificates(final RestChannel channel, final RestRequest request, final SecurityKeyStore keyStore)
        throws IOException {
        final String certType = request.param("certType").toLowerCase().trim();
        try {
            switch (certType) {
                case "http":
                    if (!httpsEnabled) {
                        badRequest(channel, "SSL for HTTP is disabled");
                        return;
                    }
                    keyStore.initHttpSSLConfig();
                    ok(channel, (builder, params) -> builder.startObject().field("message", "updated http certs").endObject());
                    break;
                case "transport":
                    keyStore.initTransportSSLConfig();
                    ok(channel, (builder, params) -> builder.startObject().field("message", "updated transport certs").endObject());
                    break;
                default:
                    Responses.forbidden(
                        channel,
                        "invalid uri path, please use /_plugins/_security/api/ssl/http/reload or "
                            + "/_plugins/_security/api/ssl/transport/reload"
                    );
                    break;
            }
        } catch (final OpenSearchSecurityException e) {
            // LOGGER.error("Reload of certificates for {} failed", certType, e);
            throw new IOException(e);
        }
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.SSL;
    }

    @Override
    public String getName() {
        return "SSL Certificates Action";
    }

    @Override
    protected RequestContentValidator createValidator(final Object... params) {
        return null;
    }

    @Override
    protected void consumeParameters(RestRequest request) {
        request.param("certType");
    }

    @Override
    protected String getResourceName() {
        return null;
    }

    @Override
    protected CType getConfigName() {
        return null;
    }

}
