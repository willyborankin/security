package org.opensearch.security;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.commons.lang3.RandomStringUtils;
import org.awaitility.Awaitility;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import java.util.Map;

import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class NoSslClusterTests {

    public static final String ADMIN_PASSWORD = RandomStringUtils.randomAlphabetic(10);

    private static final TestSecurityConfig.User USER_ADMIN = new TestSecurityConfig.User("admin").password(ADMIN_PASSWORD)
        .roles(ALL_ACCESS);

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN)
        .anonymousAuth(false)
        .nodeSettings(
            Map.of(
                SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST,
                false,
                SECURITY_SSL_HTTP_ENABLED,
                false,
                SECURITY_SSL_TRANSPORT_ENABLED,
                false
            )
        )
        .build();

    @Test
    public void testNoSslBootUp() throws Exception {
        try (TestRestClient client = cluster.getHttpRestClient(USER_ADMIN.getName(), ADMIN_PASSWORD)) {
            Awaitility.await()
                .alias("Load default configuration")
                .until(() -> client.securityHealth().getTextFromJsonBody("/status"), equalTo("UP"));
        }
    }

}
