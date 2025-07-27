/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.configuration;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchException;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.ClusterStateListener;
import org.opensearch.cluster.ClusterStateUpdateTask;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.Priority;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.core.index.Index;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.index.shard.IndexEventListener;
import org.opensearch.index.shard.IndexShard;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.state.SecurityMetadata;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecurityIndexHandler;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.opensearch.security.support.SecuritySettings.SECURITY_CONFIGURATION_INDEX_NAME;
import static org.opensearch.security.support.SnapshotRestoreHelper.isSecurityIndexRestoredFromSnapshot;

public class ConfigurationRepository implements ClusterStateListener, IndexEventListener {
    private static final Logger LOGGER = LogManager.getLogger(ConfigurationRepository.class);

    // public record IndexState(State state, boolean auditHotReloadEnabled) {
    // public static final IndexState NOT_INITIALIZED = new IndexState(State.NOT_INITIALIZED, false);
    //
    // public static IndexState initialing() {
    // return new IndexState(State.INITIALIZING, false);
    // }
    //
    // public static IndexState initialized(boolean auditHotReloadEnabled) {
    // return new IndexState(State.INITIALIZED, auditHotReloadEnabled);
    // }
    //
    // public boolean isAuditHotReloadEnabled() {
    // return auditHotReloadEnabled;
    // }
    // };

    private final String securityIndex;

    private final Cache<CType<?>, SecurityDynamicConfiguration<?>> configCache;

    private final List<ConfigurationChangeListener> configurationChangedListener;

    private final ConfigurationLoaderSecurity7 cl;

    private final Settings settings;

    private final ClusterService clusterService;

    private final AuditLog auditLog;

    private final ThreadPool threadPool;

    private DynamicConfigFactory dynamicConfigFactory;

    public static final int DEFAULT_CONFIG_VERSION = 2;

    private final boolean acceptInvalid;

    private final SecurityIndexHandler securityIndexHandler;

    private final Path configDir;

    // visible for testing
    protected ConfigurationRepository(
        final Path configDir,
        final Settings settings,
        final ThreadPool threadPool,
        final Client client,
        final ClusterService clusterService,
        final AuditLog auditLog,
        final SecurityIndexHandler securityIndexHandler,
        final ConfigurationLoaderSecurity7 configurationLoaderSecurity7
    ) {
        this.configDir = configDir;
        this.securityIndex = SECURITY_CONFIGURATION_INDEX_NAME.get(settings);
        this.settings = settings;
        this.threadPool = threadPool;
        this.clusterService = clusterService;
        this.auditLog = auditLog;
        this.configurationChangedListener = new ArrayList<>();
        this.acceptInvalid = settings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG, false);
        this.cl = configurationLoaderSecurity7;
        configCache = CacheBuilder.newBuilder().build();
        this.securityIndexHandler = securityIndexHandler;
    }

    @Override
    public void clusterChanged(final ClusterChangedEvent event) {
        // init and upload sec index on the manager node only as soon as
        // creation of index and upload config are done a new cluster state will be created.
        // in case of failures it repeats attempt after restart
        if (nodeSelectedAsManager(event)) {
            securityIndexHandler.createIndex(ActionListener.wrap(r -> {}, e -> LOGGER.error("Couldn't create index {}", securityIndex, e)));
        }
        if (!event.previousState().metadata().hasIndex(securityIndex) && event.state().metadata().hasIndex(securityIndex)) {
            LOGGER.info("Security index {} created, starting initialization", securityIndex);
            securityIndexHandler.uploadDefaultConfiguration(ActionListener.wrap(configuration -> {
                threadPool.generic().submit(() -> {
                    securityIndexHandler.loadConfiguration(configuration, ActionListener.wrap(cTypeConfigs -> {
                        notifyConfigurationListeners(cTypeConfigs);
                        final var auditConfigDocPresent = cTypeConfigs.containsKey(CType.AUDIT) && cTypeConfigs.get(CType.AUDIT).notEmpty();
                        setupAuditConfigurationIfAny(auditConfigDocPresent);
                        indexState = IndexState.initialized(auditConfigDocPresent);
                    }, e -> LOGGER.error("Couldn't reload security configuration", e)));
                    return null;
                });
            }, e -> {
                LOGGER.error("Couldn't upload default configuration to index {}", securityIndex, e);
                indexState = IndexState.NOT_INITIALIZED;
            }));
            indexState = IndexState.initialing();
        }
    }

    private boolean nodeSelectedAsManager(final ClusterChangedEvent event) {
        boolean wasClusterManager = event.previousState().nodes().isLocalNodeElectedClusterManager();
        boolean isClusterManager = event.localNodeClusterManager();
        return !wasClusterManager && isClusterManager;
    }

    private void setupAuditConfigurationIfAny(final boolean auditConfigDocPresent) {
        final Set<String> deprecatedAuditKeysInSettings = AuditConfig.getDeprecatedKeys(settings);
        if (!deprecatedAuditKeysInSettings.isEmpty()) {
            LOGGER.warn(
                "Following keys {} are deprecated in opensearch settings. They will be removed in plugin v4.0.0.0",
                deprecatedAuditKeysInSettings
            );
        }
        if (auditConfigDocPresent) {
            if (!deprecatedAuditKeysInSettings.isEmpty()) {
                LOGGER.warn("Audit configuration settings found in both index and opensearch settings (deprecated)");
            }
            LOGGER.info("Hot-reloading of audit configuration is enabled");
        } else {
            LOGGER.info(
                "Hot-reloading of audit configuration is disabled. Using configuration with defaults from opensearch settings.  Populate the configuration in index using audit.yml or securityadmin to enable it."
            );
            auditLog.setConfig(AuditConfig.from(settings));
        }
    }

    private void uploadDefaultConfiguration0() {
        securityIndexHandler.uploadDefaultConfiguration(
            ActionListener.wrap(
                configuration -> clusterService.submitStateUpdateTask(
                    "init-security-configuration",
                    new ClusterStateUpdateTask(Priority.IMMEDIATE) {
                        @Override
                        public ClusterState execute(ClusterState clusterState) throws Exception {
                            return ClusterState.builder(clusterState)
                                .putCustom(SecurityMetadata.TYPE, new SecurityMetadata(Instant.now(), configuration))
                                .build();
                        }

                        @Override
                        public void onFailure(String s, Exception e) {
                            LOGGER.error(s, e);
                        }
                    }
                ),
                e -> LOGGER.error("Couldn't upload default configuration", e)
            )
        );
    }

    public Path getConfigDirectory() {
        return configDir;
    }

    // Future<Void> executeConfigurationInitialization(final SecurityMetadata securityMetadata) {
    // if (!initalizeConfigTask.isDone()) {
    // if (initializationInProcess.compareAndSet(false, true)) {
    // return threadPool.generic().submit(() -> {
    // securityIndexHandler.loadConfiguration(securityMetadata.configuration(), ActionListener.wrap(cTypeConfigs -> {
    // notifyConfigurationListeners(cTypeConfigs);
    // final var auditConfigDocPresent = cTypeConfigs.containsKey(CType.AUDIT) && cTypeConfigs.get(CType.AUDIT).notEmpty();
    // setupAuditConfigurationIfAny(auditConfigDocPresent);
    // auditHotReloadingEnabled.getAndSet(auditConfigDocPresent);
    // initalizeConfigTask.complete(null);
    // LOGGER.info(
    // "Security configuration initialized. Applied hashes: {}",
    // securityMetadata.configuration()
    // .stream()
    // .map(c -> String.format("%s:%s", c.type().toLCString(), c.hash()))
    // .collect(Collectors.toList())
    // );
    // }, e -> LOGGER.error("Couldn't reload security configuration", e)));
    // return null;
    // });
    // }
    // }
    // return CompletableFuture.completedFuture(null);
    // }

    public boolean isAuditHotReloadingEnabled() {
        return indexState.auditHotReloadEnabled;
    }

    public static ConfigurationRepository create(
        Settings settings,
        final Path configDir,
        final ThreadPool threadPool,
        Client client,
        ClusterService clusterService,
        AuditLog auditLog
    ) {
        final var securityIndex = settings.get(
            ConfigConstants.SECURITY_CONFIG_INDEX_NAME,
            ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX
        );
        return new ConfigurationRepository(
            configDir,
            settings,
            threadPool,
            client,
            clusterService,
            auditLog,
            new SecurityIndexHandler(configDir, settings, client),
            new ConfigurationLoaderSecurity7(client, threadPool, settings, clusterService)
        );
    }

    public void setDynamicConfigFactory(DynamicConfigFactory dynamicConfigFactory) {
        this.dynamicConfigFactory = dynamicConfigFactory;
    }

    /**
     *
     * @param configurationType
     * @return can also return empty in case it was never loaded
     */
    public <T> SecurityDynamicConfiguration<T> getConfiguration(CType<T> configurationType) {
        SecurityDynamicConfiguration<?> conf = configCache.getIfPresent(configurationType);
        if (conf != null) {
            @SuppressWarnings("unchecked")
            SecurityDynamicConfiguration<T> result = (SecurityDynamicConfiguration<T>) conf.deepClone();
            return result;
        }
        return SecurityDynamicConfiguration.empty(configurationType);
    }

    private final Lock LOCK = new ReentrantLock();

    public boolean reloadConfiguration(final Collection<CType<?>> configTypes) throws ConfigUpdateAlreadyInProgressException {
        return reloadConfiguration(configTypes, false);
    }

    private boolean reloadConfiguration(final Collection<CType<?>> configTypes, final boolean fromBackgroundThread)
        throws ConfigUpdateAlreadyInProgressException {
        if (!fromBackgroundThread && indexState.state() != State.INITIALIZED) {
            LOGGER.warn("Unable to reload configuration, initalization thread has not yet completed.");
            return false;
        }
        return loadConfigurationWithLock(configTypes);
    }

    private boolean loadConfigurationWithLock(Collection<CType<?>> configTypes) {
        try {
            if (LOCK.tryLock(60, TimeUnit.SECONDS)) {
                try {
                    reloadConfiguration0(configTypes, this.acceptInvalid);
                    return true;
                } finally {
                    LOCK.unlock();
                }
            } else {
                throw new ConfigUpdateAlreadyInProgressException("A config update is already in progress");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ConfigUpdateAlreadyInProgressException("Interrupted config update");
        }
    }

    private void reloadConfiguration0(Collection<CType<?>> configTypes, boolean acceptInvalid) {
        ConfigurationMap loaded = getConfigurationsFromIndex(configTypes, false, acceptInvalid);
        notifyConfigurationListeners(loaded);
    }

    private void notifyConfigurationListeners(ConfigurationMap configuration) {
        configCache.putAll(configuration.rawMap());
        notifyAboutChanges(configuration);
    }

    public synchronized void subscribeOnChange(ConfigurationChangeListener listener) {
        configurationChangedListener.add(listener);
    }

    private synchronized void notifyAboutChanges(ConfigurationMap typeToConfig) {
        for (ConfigurationChangeListener listener : configurationChangedListener) {
            try {
                LOGGER.debug("Notify {} listener about change configuration with type {}", listener, typeToConfig);
                listener.onChange(typeToConfig);
            } catch (Exception e) {
                LOGGER.error("{} listener errored: " + e, listener, e);
                throw ExceptionsHelper.convertToOpenSearchException(e);
            }
        }
    }

    /**
     * This retrieves the config directly from the index without caching involved
     * @param configTypes
     * @param logComplianceEvent
     * @return
     */
    public ConfigurationMap getConfigurationsFromIndex(Collection<CType<?>> configTypes, boolean logComplianceEvent) {
        return getConfigurationsFromIndex(configTypes, logComplianceEvent, this.acceptInvalid);
    }

    public ConfigurationMap getConfigurationsFromIndex(
        Collection<CType<?>> configTypes,
        boolean logComplianceEvent,
        boolean acceptInvalid
    ) {

        final ThreadContext threadContext = threadPool.getThreadContext();
        final ConfigurationMap.Builder resultBuilder = new ConfigurationMap.Builder();

        try (StoredContext ctx = threadContext.stashContext()) {
            threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");

            IndexMetadata securityMetadata = clusterService.state().metadata().index(this.securityIndex);
            MappingMetadata mappingMetadata = securityMetadata == null ? null : securityMetadata.mapping();

            if (securityMetadata != null && mappingMetadata != null) {
                if ("security".equals(mappingMetadata.type())) {
                    LOGGER.debug("security index exists and was created before ES 7 (legacy layout)");
                } else {
                    LOGGER.debug("security index exists and was created with ES 7 (new layout)");
                }
                resultBuilder.with(
                    validate(cl.load(configTypes.toArray(new CType<?>[0]), 10, TimeUnit.SECONDS, acceptInvalid), configTypes.size())
                );

            } else {
                // wait (and use new layout)
                LOGGER.debug("security index not exists (yet)");
                resultBuilder.with(
                    validate(cl.load(configTypes.toArray(new CType<?>[0]), 10, TimeUnit.SECONDS, acceptInvalid), configTypes.size())
                );
            }

        } catch (Exception e) {
            throw new OpenSearchException(e);
        }

        ConfigurationMap result = resultBuilder.build();

        if (logComplianceEvent && auditLog.getComplianceConfig() != null && auditLog.getComplianceConfig().isEnabled()) {
            CType<?> configurationType = configTypes.iterator().next();
            Map<String, String> fields = new HashMap<String, String>();
            fields.put(configurationType.toLCString(), Strings.toString(MediaTypeRegistry.JSON, result.get(configurationType)));
            auditLog.logDocumentRead(this.securityIndex, configurationType.toLCString(), null, fields);
        }

        return result;
    }

    private ConfigurationMap validate(ConfigurationMap conf, int expectedSize) throws InvalidConfigException {

        if (conf == null || conf.size() != expectedSize) {
            throw new InvalidConfigException("Retrieved only partial configuration");
        }

        return conf;
    }

    public static int getDefaultConfigVersion() {
        return ConfigurationRepository.DEFAULT_CONFIG_VERSION;
    }

    @Override
    public void afterIndexShardStarted(IndexShard indexShard) {
        final ShardId shardId = indexShard.shardId();
        final Index index = shardId.getIndex();

        // Check if this is a security index shard
        if (securityIndex.equals(index.getName())) {
            // Only trigger on primary shard to avoid multiple reloads
            if (indexShard.routingEntry() != null && indexShard.routingEntry().primary()) {
                threadPool.generic().execute(() -> {
                    if (isSecurityIndexRestoredFromSnapshot(clusterService, index, securityIndex)) {
                        LOGGER.info("Security index primary shard {} started - config reloading for snapshot restore", shardId);
                        reloadConfiguration(CType.values());
                    }
                });
            }
        }
    }
}
