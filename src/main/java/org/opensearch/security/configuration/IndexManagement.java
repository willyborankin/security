package org.opensearch.security.configuration;

import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.support.ActiveShardCount;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterStateListener;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.gateway.GatewayService;
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

    public record IndexState(boolean created, boolean readyForWriting) {
        public static final IndexState NOT_INITIALIZED = new IndexState(false, false);
        public static final IndexState CREATED = new IndexState(true, false);
        public static final IndexState READY_FOR_WRITING = new IndexState(true, true);
    };

    @FunctionalInterface
    public interface IndexStateListener {
        void onIndexStateChanged(final IndexState indexState);
    }

    private final Map<String, IndexStateListener> indexStateListeners;

    private final Map<String, IndexState> previousIndexStates;

    private final Client client;

    public IndexManagement(final Client client) {
        this.indexStateListeners = new HashMap<>();
        this.previousIndexStates = new HashMap<>();
        this.client = client;
    }

    public void addIndexStateListener(final String indexName, final IndexStateListener listener) {
        indexStateListeners.put(indexName, listener);
        previousIndexStates.put(indexName, IndexState.NOT_INITIALIZED);
    }

    @Override
    public void clusterChanged(ClusterChangedEvent event) {
        if (event.state().blocks().hasGlobalBlock(GatewayService.STATE_NOT_RECOVERED_BLOCK)) return;
        if (nodeSelectedAsManager(event)) {
            createIndices(event);
        }
        indexReadyForWriting(event);
    }

    private boolean nodeSelectedAsManager(final ClusterChangedEvent event) {
        boolean wasClusterManager = event.previousState().nodes().isLocalNodeElectedClusterManager();
        boolean isClusterManager = event.localNodeClusterManager();
        return !wasClusterManager && isClusterManager;
    }

    private void createIndices(final ClusterChangedEvent event) {
        indexStateListeners.keySet().forEach(indexName -> {
            if (event.state().metadata().hasIndex(indexName)) {
                return;
            }
            if (previousIndexStates.get(indexName) != IndexState.NOT_INITIALIZED) {
                return;
            }
            try (final ThreadContext.StoredContext threadContext = client.threadPool().getThreadContext().stashContext()) {
                client.admin()
                    .indices()
                    .create(
                        new CreateIndexRequest(indexName).settings(INDEX_SETTINGS).waitForActiveShards(ActiveShardCount.ALL),
                        ActionListener.runBefore(ActionListener.wrap(r -> {
                            if (r.isAcknowledged()) {
                                indexStateListeners.get(indexName).onIndexStateChanged(IndexState.CREATED);
                                previousIndexStates.put(indexName, IndexState.CREATED);
                                LOGGER.debug("Creation of index: {} acknowledged", indexName);
                            }
                        }, e -> {
                            indexStateListeners.get(indexName).onIndexStateChanged(IndexState.NOT_INITIALIZED);
                            LOGGER.error("Couldn't create index: {}", indexName, e);
                        }), threadContext::restore)
                    );
            }
        });
    }

    private void indexReadyForWriting(final ClusterChangedEvent event) {
        indexStateListeners.forEach((indexName, indexStateListener) -> {
            if (event.state().metadata().hasIndex(indexName)) {
                final IndexMetadata indexMetadata = event.state().metadata().index(indexName);
                if (indexMetadata.getState() == IndexMetadata.State.CLOSE) {
                    LOGGER.warn("Index {} has been closed", indexName);
                    previousIndexStates.put(indexName, new IndexState(true, false));
                    indexStateListener.onIndexStateChanged(new IndexState(true, false));
                }
                final boolean readyForWriting;
                if (event.state().routingTable().hasIndex(indexName)) {
                    readyForWriting = event.state().routingTable().index(indexName).allPrimaryShardsActive();
                } else {
                    readyForWriting = false;
                }
                final IndexState indexState = new IndexState(true, readyForWriting);
                if (!previousIndexStates.get(indexName).equals(indexState)) {
                    previousIndexStates.put(indexName, indexState);
                    indexStateListener.onIndexStateChanged(indexState);
                }
            }
        });
    }

}
