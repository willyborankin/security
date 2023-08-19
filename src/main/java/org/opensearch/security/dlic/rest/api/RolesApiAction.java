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

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.ReadContext;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.configuration.MaskedField;
import org.opensearch.security.configuration.Salt;
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

import static org.opensearch.security.dlic.rest.api.RequestHandler.methodNotImplementedHandler;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class RolesApiAction extends AbstractApiAction {

    protected final static String RESOURCE_NAME = "role";

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            new Route(Method.GET, "/roles/"),
            new Route(Method.GET, "/roles/{name}"),
            new Route(Method.DELETE, "/roles/{name}"),
            new Route(Method.PUT, "/roles/{name}"),
            new Route(Method.PATCH, "/roles/"),
            new Route(Method.PATCH, "/roles/{name}")
        )
    );

    public static class RoleValidator extends RequestContentValidator {

        private static final Salt SALT = new Salt(new byte[] { 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6 });

        protected RoleValidator(ValidationContext validationContext) {
            super(validationContext);
        }

        @Override
        public ValidationResult<JsonNode> validate(RestRequest request) throws IOException {
            return super.validate(request).map(this::validateMaskedFields);
        }

        @Override
        public ValidationResult<JsonNode> validate(RestRequest request, JsonNode jsonContent) throws IOException {
            return super.validate(request, jsonContent).map(this::validateMaskedFields);
        }

        private ValidationResult<JsonNode> validateMaskedFields(final JsonNode content) {
            final ReadContext ctx = JsonPath.parse(content.toString());
            final List<String> maskedFields = ctx.read("$..masked_fields[*]");
            if (maskedFields != null) {
                for (String mf : maskedFields) {
                    if (!validateMaskedFieldSyntax(mf)) {
                        this.validationError = ValidationError.WRONG_DATATYPE;
                        return ValidationResult.error(RestStatus.BAD_REQUEST, this);
                    }
                }
            }
            return ValidationResult.success(content);
        }

        private boolean validateMaskedFieldSyntax(String mf) {
            try {
                new MaskedField(mf, SALT).isValid();
            } catch (Exception e) {
                wrongDataTypes.put("Masked field not valid: " + mf, e.getMessage());
                return false;
            }
            return true;
        }

    }

    @Inject
    public RolesApiAction(
        Settings settings,
        final Path configPath,
        AdminDNs adminDNs,
        ConfigurationRepository cl,
        ClusterService cs,
        final PrincipalExtractor principalExtractor,
        final PrivilegesEvaluator evaluator,
        ThreadPool threadPool,
        AuditLog auditLog
    ) {
        super(settings, configPath, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
        this.requestHandlersBuilder.configureRequestHandlers(this::rolesApiRequestHandlers);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected CType getConfigType() {
        return CType.ROLES;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.ROLES;
    }

    private void rolesApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.onChangeRequest(Method.PATCH, this::processPatchRequest).override(Method.POST, methodNotImplementedHandler);
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
            public ValidationResult<SecurityConfiguration> hasRightsToChangeEntity(SecurityConfiguration securityConfiguration)
                throws IOException {
                return EndpointValidator.super.hasRightsToChangeEntity(securityConfiguration).map(ignore -> {
                    if (isCurrentUserAdmin()) {
                        return ValidationResult.success(securityConfiguration);
                    }
                    return canChangeObjectWithRestAdminPermissions(securityConfiguration);
                });
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return new RoleValidator(new RequestContentValidator.ValidationContext() {
                    @Override
                    public Object[] params() {
                        return params;
                    }

                    @Override
                    public Settings settings() {
                        return settings;
                    }

                    @Override
                    public Map<String, DataType> allowedKeys() {
                        final ImmutableMap.Builder<String, DataType> allowedKeys = ImmutableMap.builder();
                        if (isCurrentUserAdmin()) allowedKeys.put("reserved", DataType.BOOLEAN);
                        return allowedKeys.put("cluster_permissions", DataType.ARRAY)
                            .put("tenant_permissions", DataType.ARRAY)
                            .put("index_permissions", DataType.ARRAY)
                            .put("description", DataType.STRING)
                            .build();
                    }
                });
            }
        };
    }

}
