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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.threadpool.ThreadPool;

import java.nio.file.Path;
import java.util.List;

import static org.opensearch.security.dlic.rest.api.Responses.internalSeverError;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class FlushCacheApiAction extends AbstractApiAction {

    private final static Logger LOGGER = LogManager.getLogger(FlushCacheApiAction.class);

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            new Route(Method.DELETE, "/cache"),
            new Route(Method.GET, "/cache"),
            new Route(Method.PUT, "/cache"),
            new Route(Method.POST, "/cache")
        )
    );

    @Inject
    public FlushCacheApiAction(
        final Settings settings,
        final Path configPath,
        final RestController controller,
        final Client client,
        final AdminDNs adminDNs,
        final ConfigurationRepository cl,
        final ClusterService cs,
        final PrincipalExtractor principalExtractor,
        final PrivilegesEvaluator evaluator,
        ThreadPool threadPool,
        AuditLog auditLog
    ) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
        this.requestHandlersBuilder.configureRequestHandlers(this::flushCacheApiRequestHandlers);
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
    protected Endpoint getEndpoint() {
        return Endpoint.CACHE;
    }

    private void flushCacheApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.allMethodsNotImplemented().override(Method.DELETE, (channel, request, client) -> {
            client.execute(
                ConfigUpdateAction.INSTANCE,
                new ConfigUpdateRequest(CType.lcStringValues().toArray(new String[0])),
                new ActionListener<>() {

                    @Override
                    public void onResponse(ConfigUpdateResponse configUpdateResponse) {
                        if (configUpdateResponse.hasFailures()) {
                            LOGGER.error("Cannot flush cache due to", configUpdateResponse.failures().get(0));
                            internalSeverError(
                                channel,
                                "Cannot flush cache due to " + configUpdateResponse.failures().get(0).getMessage() + "."
                            );
                            return;
                        }
                        LOGGER.debug("cache flushed successfully");
                        ok(channel, "Cache flushed successfully.");
                    }

                    @Override
                    public void onFailure(final Exception e) {
                        LOGGER.error("Cannot flush cache due to", e);
                        internalSeverError(channel, "Cannot flush cache due to " + e.getMessage() + ".");
                    }

                }
            );
        });
    }

    @Override
    protected String getResourceName() {
        // not needed
        return null;
    }

    @Override
    protected CType getConfigType() {
        return null;
    }

    @Override
    protected void consumeParameters(final RestRequest request) {
        // not needed
    }
}
