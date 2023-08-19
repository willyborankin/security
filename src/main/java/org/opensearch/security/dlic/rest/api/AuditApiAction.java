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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.configuration.StaticResourceException;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.opensearch.security.dlic.rest.api.RequestHandler.methodNotImplementedHandler;
import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.conflictMessage;
import static org.opensearch.security.dlic.rest.api.Responses.methodNotImplementedMessage;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * Rest handler for fetching and updating audit configuration.
 * Supported REST endpoints
 * GET _opendistro/_security/api/audit/
 * {
 *   "config" : {
 *     "audit" : {
 *       "enable_rest" : true,
 *       "disabled_rest_categories" : [
 *         "GRANTED_PRIVILEGES",
 *         "SSL_EXCEPTION"
 *       ],
 *       "enable_transport" : true,
 *       "disabled_transport_categories" : [
 *         "GRANTED_PRIVILEGES",
 *         "AUTHENTICATED"
 *       ],
 *       "resolve_bulk_requests" : false,
 *       "log_request_body" : true,
 *       "resolve_indices" : true,
 *       "exclude_sensitive_headers" : true,
 *       "ignore_users" : [
 *         "kibanaserver"
 *       ],
 *       "ignore_requests" : [ ]
 *     },
 *     "compliance" : {
 *       "internal_config" : true,
 *       "external_config" : true,
 *       "read_metadata_only" : true,
 *       "read_watched_fields" : { },
 *       "read_ignore_users" : [ ],
 *       "write_metadata_only" : true,
 *       "write_log_diffs" : false,
 *       "write_watched_indices" : [ ],
 *       "write_ignore_users" : [ ]
 *     }
 *   }
 * }
 *
 * PUT _opendistro/_security/api/audit/config
 * {
 *   "audit":{
 *     "enable_rest":true,
 *     "disabled_rest_categories":[
 *       "GRANTED_PRIVILEGES",
 *       "SSL_EXCEPTION"
 *     ],
 *     "enable_transport":true,
 *     "disabled_transport_categories":[
 *       "GRANTED_PRIVILEGES",
 *       "AUTHENTICATED"
 *     ],
 *     "resolve_bulk_requests":false,
 *     "log_request_body":true,
 *     "resolve_indices":true,
 *     "exclude_sensitive_headers":true,
 *     "ignore_users":[ ],
 *     "ignore_requests":[ ]
 *   },
 *   "compliance":{
 *     "internal_config":true,
 *     "external_config":true,
 *     "read_metadata_only":true,
 *     "read_watched_fields":{ },
 *     "read_ignore_users":[ ],
 *     "write_metadata_only":true,
 *     "write_log_diffs":false,
 *     "write_watched_indices":[ ],
 *     "write_ignore_users":[ ]
 *   }
 * }
 *
 * PATCH _opendistro/_security/api/audit
 * [{"op": "replace", "path": "/config/audit/enable_rest", "value": "true"}]
 * [{"op": "replace", "path": "/config/compliance/internal_config", "value": "true"}]
 */
public class AuditApiAction extends AbstractApiAction {
    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            new Route(RestRequest.Method.GET, "/audit/"),
            new Route(RestRequest.Method.PUT, "/audit/{name}"),
            new Route(RestRequest.Method.PATCH, "/audit/")
        )
    );

    private static final String RESOURCE_NAME = "config";
    @VisibleForTesting
    public static final String READONLY_FIELD = "_readonly";
    @VisibleForTesting
    public static final String STATIC_RESOURCE = "/static_config/static_audit.yml";
    private final List<String> readonlyFields;

    public static class AuditRequestContentValidator extends RequestContentValidator {
        private static final Set<AuditCategory> DISABLED_REST_CATEGORIES = ImmutableSet.of(
            AuditCategory.BAD_HEADERS,
            AuditCategory.SSL_EXCEPTION,
            AuditCategory.AUTHENTICATED,
            AuditCategory.FAILED_LOGIN,
            AuditCategory.GRANTED_PRIVILEGES,
            AuditCategory.MISSING_PRIVILEGES
        );

        private static final Set<AuditCategory> DISABLED_TRANSPORT_CATEGORIES = ImmutableSet.of(
            AuditCategory.BAD_HEADERS,
            AuditCategory.SSL_EXCEPTION,
            AuditCategory.AUTHENTICATED,
            AuditCategory.FAILED_LOGIN,
            AuditCategory.GRANTED_PRIVILEGES,
            AuditCategory.MISSING_PRIVILEGES,
            AuditCategory.INDEX_EVENT,
            AuditCategory.OPENDISTRO_SECURITY_INDEX_ATTEMPT
        );

        protected AuditRequestContentValidator(ValidationContext validationContext) {
            super(validationContext);
        }

        @Override
        public ValidationResult<JsonNode> validate(RestRequest request) throws IOException {
            return super.validate(request).map(this::validateAuditPayload);
        }

        @Override
        public ValidationResult<JsonNode> validate(RestRequest request, JsonNode jsonContent) throws IOException {
            return super.validate(request, jsonContent).map(this::validateAuditPayload);
        }

        private ValidationResult<JsonNode> validateAuditPayload(final JsonNode jsonContent) {
            try {
                // try parsing to target type
                final AuditConfig auditConfig = DefaultObjectMapper.readTree(jsonContent, AuditConfig.class);
                final AuditConfig.Filter filter = auditConfig.getFilter();
                if (!DISABLED_REST_CATEGORIES.containsAll(filter.getDisabledRestCategories())) {
                    throw new IllegalArgumentException("Invalid REST categories passed in the request");
                }
                if (!DISABLED_TRANSPORT_CATEGORIES.containsAll(filter.getDisabledTransportCategories())) {
                    throw new IllegalArgumentException("Invalid transport categories passed in the request");
                }
                return ValidationResult.success(jsonContent);
            } catch (final Exception e) {
                // this.content is not valid json
                this.validationError = ValidationError.BODY_NOT_PARSEABLE;
                LOGGER.error("Invalid content passed in the request", e);
                return ValidationResult.error(RestStatus.BAD_REQUEST, this);
            }
        }
    }

    public AuditApiAction(
        final Settings settings,
        final Path configPath,
        final AdminDNs adminDNs,
        final ConfigurationRepository cl,
        final ClusterService cs,
        final PrincipalExtractor principalExtractor,
        final PrivilegesEvaluator privilegesEvaluator,
        final ThreadPool threadPool,
        final AuditLog auditLog
    ) {
        super(settings, configPath, adminDNs, cl, cs, principalExtractor, privilegesEvaluator, threadPool, auditLog);
        try {
            this.readonlyFields = DefaultObjectMapper.YAML_MAPPER.readValue(
                this.getClass().getResourceAsStream(STATIC_RESOURCE),
                new TypeReference<Map<String, List<String>>>() {
                }
            ).get(READONLY_FIELD);
            if (!AuditConfig.FIELD_PATHS.containsAll(this.readonlyFields)) {
                throw new StaticResourceException("Invalid read-only field paths provided in static resource file " + STATIC_RESOURCE);
            }
        } catch (IOException e) {
            throw new StaticResourceException("Unable to load audit static resource file", e);
        }
        this.requestHandlersBuilder.configureRequestHandlers(this::auditApiRequestHandlers);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.AUDIT;
    }

    @Override
    protected CType getConfigType() {
        return CType.AUDIT;
    }

    private void auditApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.onGetRequest(
            request -> withEnabledAuditApi(request).map(this::processGetRequest).map(securityConfiguration -> {
                final var configuration = securityConfiguration.configuration();
                configuration.putCObject(READONLY_FIELD, readonlyFields);
                return ValidationResult.success(securityConfiguration);
            })
        )
            .onChangeRequest(RestRequest.Method.PATCH, request -> withEnabledAuditApi(request).map(this::processPatchRequest))
            .onChangeRequest(
                RestRequest.Method.PUT,
                request -> withEnabledAuditApi(request).map(this::withConfigEntityNameOnly).map(ignore -> processPutRequest(request))
            )
            .override(RestRequest.Method.POST, methodNotImplementedHandler)
            .override(RestRequest.Method.DELETE, methodNotImplementedHandler);
    }

    private ValidationResult<RestRequest> withEnabledAuditApi(final RestRequest request) {
        if (!cl.isAuditHotReloadingEnabled()) {
            return ValidationResult.error(RestStatus.NOT_IMPLEMENTED, methodNotImplementedMessage(request.method()));
        }
        return ValidationResult.success(request);
    }

    private ValidationResult<String> withConfigEntityNameOnly(final RestRequest request) {
        final var name = nameParam(request);
        if (!RESOURCE_NAME.equals(name)) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("name must be config"));
        }
        return ValidationResult.success(name);
    }

    @Override
    protected EndpointValidator createEndpointValidator() {
        return new EndpointValidator() {

            @Override
            public String resourceName() {
                return RESOURCE_NAME;
            }

            @Override
            public Endpoint endpoint() {
                return getEndpoint();
            }

            @Override
            public RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator() {
                return restApiAdminPrivilegesEvaluator;
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigChange(SecurityConfiguration securityConfiguration) throws IOException {
                return EndpointValidator.super.onConfigChange(securityConfiguration).map(this::verifyNotReadonlyFieldUpdated);
            }

            private ValidationResult<SecurityConfiguration> verifyNotReadonlyFieldUpdated(
                final SecurityConfiguration securityConfiguration
            ) {
                if (!restApiAdminPrivilegesEvaluator().isCurrentUserAdminFor(endpoint())) {
                    final var existingResource = Utils.convertJsonToJackson(securityConfiguration.configuration(), false)
                        .get(RESOURCE_NAME);
                    final var targetResource = securityConfiguration.requestContent();
                    if (readonlyFields.stream().anyMatch(path -> !existingResource.at(path).equals(targetResource.at(path)))) {
                        return ValidationResult.error(RestStatus.CONFLICT, conflictMessage("Attempted to update read-only property."));
                    }
                }
                return ValidationResult.success(securityConfiguration);
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return new AuditRequestContentValidator(new RequestContentValidator.ValidationContext() {
                    @Override
                    public Object[] params() {
                        return params;
                    }

                    @Override
                    public Settings settings() {
                        return settings;
                    }

                    @Override
                    public Map<String, RequestContentValidator.DataType> allowedKeys() {
                        return ImmutableMap.of("enabled", DataType.BOOLEAN, "audit", DataType.OBJECT, "compliance", DataType.OBJECT);
                    }
                });
            }
        };
    }

}
