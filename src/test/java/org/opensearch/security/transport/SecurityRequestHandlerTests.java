/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.transport;

import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.ssl.SslExceptionHandler;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.transport.SSLConfig;
import org.opensearch.security.ssl.transport.SecuritySSLRequestHandler;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.UserFactory;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportChannel;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestHandler;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SecurityRequestHandlerTests {

    @Mock
    private AuditLog auditLog;

    @Mock
    private InterClusterRequestEvaluator requestEvalProvider;

    @Mock
    private ClusterService clusterService;

    @Mock
    private PrincipalExtractor principalExtractor;

    @Mock
    private SSLConfig sslConfig;

    @Mock
    private SslExceptionHandler sslExceptionHandler;

    @Mock
    private ClusterInfoHolder clusterInfoHolder;

    private ThreadPool threadPool;
    private UserFactory userFactory;
    private RemoteClusterIdentityPolicy remoteClusterIdentityPolicy;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        Settings settings = Settings.builder().put("node.name", SecurityRequestHandlerTests.class.getSimpleName()).build();
        threadPool = new ThreadPool(settings);
        userFactory = new UserFactory.Simple();
        remoteClusterIdentityPolicy = new RemoteClusterIdentityPolicy(false);
    }

    @After
    public void tearDown() {
        if (threadPool != null) {
            threadPool.shutdown();
        }
    }

    @Test
    public void testDirectChannelDelegatesToActualHandler() throws Exception {
        AtomicBoolean called = new AtomicBoolean(false);
        TransportRequestHandler<TransportRequest> actualHandler = (request, channel, task) -> called.set(true);

        SecurityRequestHandler<TransportRequest> handler = new SecurityRequestHandler<>(
            "indices:data/read/get",
            actualHandler,
            threadPool,
            auditLog,
            requestEvalProvider,
            clusterService,
            userFactory,
            remoteClusterIdentityPolicy
        );

        TransportRequest request = mock(TransportRequest.class);
        TransportChannel channel = mock(TransportChannel.class);
        when(channel.getChannelType()).thenReturn("direct");
        Task task = mock(Task.class);
        when(task.getAction()).thenReturn("indices:data/read/get");

        handler.messageReceived(request, channel, task);

        assertTrue("Actual handler should be called for direct channel", called.get());
    }

    @Test
    public void testStreamChannelDelegatesToActualHandler() throws Exception {
        AtomicBoolean called = new AtomicBoolean(false);
        TransportRequestHandler<TransportRequest> actualHandler = (request, channel, task) -> called.set(true);

        SecurityRequestHandler<TransportRequest> handler = new SecurityRequestHandler<>(
            "indices:data/read/search",
            actualHandler,
            threadPool,
            auditLog,
            requestEvalProvider,
            clusterService,
            userFactory,
            remoteClusterIdentityPolicy
        );

        TransportRequest request = mock(TransportRequest.class);
        TransportChannel channel = mock(TransportChannel.class);
        when(channel.getChannelType()).thenReturn("stream-transport");
        Task task = mock(Task.class);
        when(task.getAction()).thenReturn("indices:data/read/search");

        handler.messageReceived(request, channel, task);

        assertTrue("Actual handler should be called for stream-transport channel", called.get());
    }

    @Test
    public void testDualModeSkipDelegatesToActualHandler() throws Exception {
        AtomicBoolean called = new AtomicBoolean(false);
        TransportRequestHandler<TransportRequest> actualHandler = (request, channel, task) -> called.set(true);

        SecurityRequestHandler<TransportRequest> handler = new SecurityRequestHandler<>(
            "indices:data/read/search",
            actualHandler,
            threadPool,
            auditLog,
            requestEvalProvider,
            clusterService,
            userFactory,
            remoteClusterIdentityPolicy
        );

        threadPool.getThreadContext().putTransient(ConfigConstants.SECURITY_SSL_DUAL_MODE_SKIP_SECURITY, Boolean.TRUE);

        TransportRequest request = mock(TransportRequest.class);
        TransportChannel channel = mock(TransportChannel.class);
        when(channel.getChannelType()).thenReturn("transport");
        Task task = mock(Task.class);
        when(task.getAction()).thenReturn("indices:data/read/search");

        handler.messageReceived(request, channel, task);

        assertTrue("Actual handler should be called when dual mode skips security", called.get());
    }

    @Test
    public void testMissingSslClientCertificatesRejectsRequest() throws Exception {
        AtomicBoolean called = new AtomicBoolean(false);
        TransportRequestHandler<TransportRequest> actualHandler = (request, channel, task) -> called.set(true);

        SecurityRequestHandler<TransportRequest> handler = new SecurityRequestHandler<>(
            "indices:data/read/search",
            actualHandler,
            threadPool,
            auditLog,
            requestEvalProvider,
            clusterService,
            userFactory,
            remoteClusterIdentityPolicy
        );

        TransportRequest request = mock(TransportRequest.class);
        TransportChannel channel = mock(TransportChannel.class);
        when(channel.getChannelType()).thenReturn("transport");
        Task task = mock(Task.class);
        when(task.getAction()).thenReturn("indices:data/read/search");

        handler.messageReceived(request, channel, task);

        verify(channel).sendResponse(any(OpenSearchSecurityException.class));
        verify(auditLog).logSSLException(eq(request), any(OpenSearchSecurityException.class), eq("indices:data/read/search"), eq(task));
        assertTrue("Actual handler must NOT be called when SSL certs are missing", !called.get());
    }

    @Test
    public void testInterceptorGetHandlerCreatesComposedChain() {
        SecurityInterceptor interceptor = new SecurityInterceptor(
            Settings.EMPTY,
            threadPool,
            null,
            auditLog,
            principalExtractor,
            requestEvalProvider,
            clusterService,
            sslExceptionHandler,
            clusterInfoHolder,
            sslConfig,
            () -> false,
            userFactory,
            remoteClusterIdentityPolicy
        );

        TransportRequestHandler<TransportRequest> actualHandler = (request, channel, task) -> {};
        TransportRequestHandler<TransportRequest> chainedHandler = interceptor.getHandler("testAction", actualHandler);

        assertNotNull(chainedHandler);
        assertThat(chainedHandler, instanceOf(SecuritySSLRequestHandler.class));
    }
}
