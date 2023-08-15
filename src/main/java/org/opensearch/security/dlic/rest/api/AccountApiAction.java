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
import com.google.common.collect.ImmutableSet;
import org.apache.commons.lang3.tuple.Triple;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.Hashed;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import static org.opensearch.security.dlic.rest.support.Utils.hash;

/**
 * Rest API action to fetch or update account details of the signed-in user.
 * Currently this action serves GET and PUT request for /_opendistro/_security/api/account endpoint
 */
public class AccountApiAction extends AbstractApiAction {

    private static final String RESOURCE_NAME = "account";
    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(new Route(Method.GET, "/account"), new Route(Method.PUT, "/account"))
    );

    private final PrivilegesEvaluator privilegesEvaluator;
    private final ThreadContext threadContext;

    public AccountApiAction(
        Settings settings,
        Path configPath,
        RestController controller,
        Client client,
        AdminDNs adminDNs,
        ConfigurationRepository cl,
        ClusterService cs,
        PrincipalExtractor principalExtractor,
        PrivilegesEvaluator privilegesEvaluator,
        ThreadPool threadPool,
        AuditLog auditLog
    ) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, privilegesEvaluator, threadPool, auditLog);
        this.privilegesEvaluator = privilegesEvaluator;
        this.threadContext = threadPool.getThreadContext();
        this.requestHandlersBuilder.configureRequestHandlers(this::accountApiRequestHandlers);
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
        return routes;
    }

    @Override
    protected String getResourceName() {
        return RESOURCE_NAME;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.ACCOUNT;
    }

    @Override
    protected CType getConfigType() {
        return CType.INTERNALUSERS;
    }

    private void accountApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        // spotless:off
        requestHandlersBuilder.allMethodsNotImplemented()
            .override(Method.GET, (channel, request, client) ->
                    withUserAndRemoteAddress().map(
                            userAndRemoteAddress ->
                                    loadConfiguration(getConfigType(), false, false)
                                            .map(configuration ->
                                                    ValidationResult.success(
                                                            Triple.of(
                                                                    userAndRemoteAddress.getLeft(),
                                                                    userAndRemoteAddress.getRight(), configuration
                                                            )
                                                    )
                                            )
                    ).valid(userRemoteAddressAndConfig -> {
                        final var user = userRemoteAddressAndConfig.getLeft();
                        final var remoteAddress = userRemoteAddressAndConfig.getMiddle();
                        final var configuration = userRemoteAddressAndConfig.getRight();
                        userAccount(channel, user, remoteAddress, configuration);
                    }).error((status, toXContent) -> Responses.response(channel, status, toXContent))
            ).onChangeRequest(Method.PUT, request ->
                        withUserAndRemoteAddress()
                                .map(userAndRemoteAddress ->
                                        loadConfigurationWithRequestContent(
                                                userAndRemoteAddress.getLeft().getName(),
                                                request,
                                                endpointValidator.createRequestContentValidator()
                                        )
                                )
                                .map(endpointValidator::entityExists)
                                .map(endpointValidator::onConfigChange)
                                .map(this::passwordCanBeValidated)
                                .map(this::updateUserPassword)
        );
        // spotless:on
    }

    private void userAccount(
        final RestChannel channel,
        final User user,
        final TransportAddress remoteAddress,
        final SecurityDynamicConfiguration<?> configuration
    ) {
        final var securityRoles = privilegesEvaluator.mapRoles(user, remoteAddress);
        ok(
            channel,
            (builder, params) -> builder.startObject()
                .field("user_name", user.getName())
                .field("is_reserved", isReserved(configuration, user.getName()))
                .field("is_hidden", configuration.isHidden(user.getName()))
                .field("is_internal_user", configuration.exists(user.getName()))
                .field("user_requested_tenant", user.getRequestedTenant())
                .field("backend_roles", user.getRoles())
                .field("custom_attribute_names", user.getCustomAttributesMap().keySet())
                .field("tenants", privilegesEvaluator.mapTenants(user, securityRoles))
                .field("roles", securityRoles)
                .endObject()
        );
    }

    private ValidationResult<SecurityConfiguration> passwordCanBeValidated(final SecurityConfiguration securityConfiguration) {
        final var username = securityConfiguration.entityName();
        final var content = securityConfiguration.requestContent();
        final var currentPassword = content.get("current_password").asText();
        final var internalUserEntry = (Hashed) securityConfiguration.configuration().getCEntry(username);
        final var currentHash = internalUserEntry.getHash();
        if (currentHash == null || !OpenBSDBCrypt.checkPassword(currentHash, currentPassword.toCharArray())) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("Could not validate your current password."));
        }
        return ValidationResult.success(securityConfiguration);
    }

    private ValidationResult<SecurityConfiguration> updateUserPassword(final SecurityConfiguration securityConfiguration) {
        final var username = securityConfiguration.entityName();
        final var securityJsonNode = new SecurityJsonNode(securityConfiguration.requestContent());
        final var internalUserEntry = (Hashed) securityConfiguration.configuration().getCEntry(username);
        // if password is set, it takes precedence over hash
        final var password = securityJsonNode.get("password").asString();
        final String hash;
        if (Strings.isNullOrEmpty(password)) {
            hash = securityJsonNode.get("hash").asString();
        } else {
            hash = hash(password.toCharArray());
        }
        if (Strings.isNullOrEmpty(hash)) {
            return ValidationResult.error(
                RestStatus.BAD_REQUEST,
                badRequestMessage("Both provided password and hash cannot be null/empty.")
            );
        }
        internalUserEntry.setHash(hash);
        return ValidationResult.success(securityConfiguration);
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
            public RequestContentValidator createRequestContentValidator(Object... params) {
                final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                return RequestContentValidator.of(new RequestContentValidator.ValidationContext() {
                    @Override
                    public Object[] params() {
                        return new Object[] { user.getName() };
                    }

                    @Override
                    public Settings settings() {
                        return settings;
                    }

                    @Override
                    public Set<String> mandatoryKeys() {
                        return ImmutableSet.of("current_password");
                    }

                    @Override
                    public Map<String, RequestContentValidator.DataType> allowedKeys() {
                        return ImmutableMap.of("hash", DataType.STRING, "password", DataType.STRING, "current_password", DataType.STRING);
                    }
                });
            }
        };
    }

}
