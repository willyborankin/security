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

package org.opensearch.security.support;

import org.opensearch.common.settings.Setting;

public class SecuritySettings {

    public static final Setting<String> SECURITY_CONFIGURATION_INDEX_NAME = Setting.simpleString(
        ConfigConstants.SECURITY_CONFIG_INDEX_NAME,
        ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX,
        Setting.Property.NodeScope,
        Setting.Property.Filtered
    );

    public static final Setting<Boolean> LEGACY_OPENDISTRO_SSL_DUAL_MODE_SETTING = Setting.boolSetting(
        ConfigConstants.LEGACY_OPENDISTRO_SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED,
        false,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Deprecated
    ); // Not filtered
    public static final Setting<Boolean> SSL_DUAL_MODE_SETTING = Setting.boolSetting(
        ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED,
        LEGACY_OPENDISTRO_SSL_DUAL_MODE_SETTING,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    ); // Not filtered

    public static final Setting<Integer> CACHE_TTL_SETTING = Setting.intSetting(
        ConfigConstants.SECURITY_CACHE_TTL_MINUTES,
        60,
        0,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    ); // Not filtered

    public static final Setting<Boolean> ALLOW_DEFAULT_INIT_SECURITY_INDEX = Setting.boolSetting(
        "plugins.security.allow_default_init_securityindex",
        false,
        Setting.Property.NodeScope,
        Setting.Property.Filtered
    );

    public static final Setting<Boolean> ALLOW_DEFAULT_INIT_SECURITY_INDEX_USE_CLUSTER_STATE = Setting.boolSetting(
        "plugins.security.allow_default_init_securityindex.use_cluster_state",
        false,
        Setting.Property.NodeScope,
        Setting.Property.Filtered
    );

}
