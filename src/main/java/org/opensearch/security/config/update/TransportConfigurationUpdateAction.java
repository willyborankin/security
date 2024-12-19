package org.opensearch.security.config.update;

import java.io.IOException;
import java.util.EnumSet;
import java.util.Set;

import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.TransportBulkAction;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.clustermanager.TransportClusterManagerNodeAction;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.ClusterStateUpdateTask;
import org.opensearch.cluster.block.ClusterBlock;
import org.opensearch.cluster.block.ClusterBlockException;
import org.opensearch.cluster.block.ClusterBlockLevel;
import org.opensearch.cluster.block.ClusterBlocks;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.Priority;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import static org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_CONFIG_INDEX_NAME;

public class TransportConfigurationUpdateAction extends TransportClusterManagerNodeAction<
    ConfigurationUpdateRequest,
    ConfigurationUpdateResponse> {

    private final static ClusterBlock CONFIGURATION_UPDATE_BLOCK = new ClusterBlock(
        1000,
        "security configuration update (api)",
        false,
        false,
        false,
        RestStatus.FORBIDDEN,
        EnumSet.noneOf(ClusterBlockLevel.class)
    );

    private final TransportBulkAction bulkAction;

    @Inject
    public TransportConfigurationUpdateAction(
        final TransportService transportService,
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final ActionFilters actionFilters,
        final IndexNameExpressionResolver indexNameExpressionResolver,
        final TransportBulkAction bulkAction
    ) {
        super(
            ConfigurationUpdateAction.ACTION_NAME,
            transportService,
            clusterService,
            threadPool,
            actionFilters,
            ConfigurationUpdateRequest::new,
            indexNameExpressionResolver
        );
        this.bulkAction = bulkAction;
    }

    @Override
    protected String executor() {
        return ThreadPool.Names.SAME; // async asap
    }

    @Override
    protected ConfigurationUpdateResponse read(final StreamInput in) throws IOException {
        return new ConfigurationUpdateResponse(in);
    }

    private String securityIndexName() {
        return clusterService.getSettings().get(SECURITY_CONFIG_INDEX_NAME, OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
    }

    @Override
    protected ClusterBlockException checkBlock(final ConfigurationUpdateRequest request, final ClusterState state) {
        if (state.blocks().hasIndexBlock(securityIndexName(), CONFIGURATION_UPDATE_BLOCK)) {
            return new ClusterBlockException(Set.of(CONFIGURATION_UPDATE_BLOCK));
        }
        return state.blocks().indexBlockedException(ClusterBlockLevel.WRITE, securityIndexName());
    }

    @Override
    protected void clusterManagerOperation(
        final ConfigurationUpdateRequest request,
        final ClusterState state,
        final ActionListener<ConfigurationUpdateResponse> listener
    ) throws Exception {
        clusterService.submitStateUpdateTask("update-security-configuration", new ClusterStateUpdateTask(Priority.IMMEDIATE) {
            @Override
            public ClusterState execute(ClusterState clusterState) throws Exception {
                final var blocks = ClusterBlocks.builder().blocks(clusterState.blocks());
                blocks.addIndexBlock(securityIndexName(), CONFIGURATION_UPDATE_BLOCK);
                return ClusterState.builder(clusterState).blocks(blocks).build();
            }

            @Override
            public void clusterStateProcessed(final String source, final ClusterState oldState, final ClusterState newState) {
                threadPool.executor(ThreadPool.Names.MANAGEMENT).submit(() -> {
                    bulkAction.execute(
                        new BulkRequest().add(
                            new IndexRequest(securityIndexName()).id(CType.ALLOWLIST.toLCString())
                                .source(CType.ALLOWLIST.toLCString(), "OOOOOOOO")
                        ).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).timeout(request.timeout()),
                        ActionListener.wrap(r -> {
                            BulkItemResponse bulkItemResponse = r.getItems()[0];
                            if (!bulkItemResponse.isFailed()) {
                                final DocWriteResponse response = bulkItemResponse.getResponse();
                                listener.onResponse(new ConfigurationUpdateResponse());
                            } else {
                                listener.onFailure(bulkItemResponse.getFailure().getCause());
                            }
                        }, listener::onFailure)
                    );
                });
            }

            @Override
            public void onFailure(String s, Exception e) {
                listener.onFailure(e);
            }
        });
    }

}
