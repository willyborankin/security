package org.opensearch.security.configuration;

import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.support.ActiveShardCount;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterStateListener;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.transport.client.Client;

public class IndexManagement implements ClusterStateListener {

    private final static Logger LOGGER = LogManager.getLogger(IndexManagement.class);

    public final static Map<String, Object> INDEX_SETTINGS = Map.of(
        "index.number_of_shards",
        1,
        "index.auto_expand_replicas",
        "0-all",
        "index.hidden",
        "true"
    );

    public enum State {
        NOT_INITIALIZED,
        INITIALIZING,
        INITIALIZED,
        INITIALIZATION_FAILED
    }

    public record IndexState(State state, boolean auditHotReloadEnabled) {
        public static final IndexState NOT_INITIALIZED = new IndexState(State.NOT_INITIALIZED, false);

        public static final IndexState INITIALIZATION_FAILED = new IndexState(State.INITIALIZATION_FAILED, false);

        public static IndexState initializing() {
            return new IndexState(State.INITIALIZING, false);
        }

        public static IndexState initialized(boolean auditHotReloadEnabled) {
            return new IndexState(State.INITIALIZED, auditHotReloadEnabled);
        }

        public boolean isAuditHotReloadEnabled() {
            return auditHotReloadEnabled;
        }
    };

    @FunctionalInterface
    public interface IndexStateListener {
        void onIndexStateChanged(final IndexState indexState);
    }

    private final Map<String, IndexStateListener> indexStateListeners;

    private final Client client;

    public IndexManagement(final Client client) {
        this.indexStateListeners = new HashMap<>();
        this.client = client;
    }

    public void addIndexStateListener(final String indexName, final IndexStateListener listener) {
        indexStateListeners.put(indexName, listener);
    }

    @Override
    public void clusterChanged(ClusterChangedEvent event) {
        if (nodeSelectedAsManager(event)) {
            indexStateListeners.keySet().forEach(indexName -> {
                try (final ThreadContext.StoredContext threadContext = client.threadPool().getThreadContext().stashContext()) {
                    client.admin()
                        .indices()
                        .create(
                            new CreateIndexRequest(indexName).settings(INDEX_SETTINGS).waitForActiveShards(ActiveShardCount.ALL),
                            ActionListener.runBefore(ActionListener.wrap(r -> {
                                if (r.isAcknowledged()) {
                                    indexStateListeners.get(indexName).onIndexStateChanged(IndexState.initializing());
                                    LOGGER.debug("Creation of index: {} acknowledged", indexName);
                                }
                            }, e -> {
                                indexStateListeners.get(indexName).onIndexStateChanged(IndexState.INITIALIZATION_FAILED);
                                LOGGER.error("Couldn't create index: {}", indexName, e);
                            }), threadContext::restore)
                        );
                }
            });
        }
        indexStateListeners.keySet().forEach(indexName -> {
            if (!event.previousState().metadata().hasIndex(indexName) && event.state().metadata().hasIndex(indexName)) {
                indexStateListeners.get(indexName).onIndexStateChanged(IndexState.initialized(false));
            }
        });
    }

    private boolean nodeSelectedAsManager(final ClusterChangedEvent event) {
        boolean wasClusterManager = event.previousState().nodes().isLocalNodeElectedClusterManager();
        boolean isClusterManager = event.localNodeClusterManager();
        return !wasClusterManager && isClusterManager;
    }

}
