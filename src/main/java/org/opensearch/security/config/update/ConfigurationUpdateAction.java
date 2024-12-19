package org.opensearch.security.config.update;

import org.opensearch.action.ActionType;

public class ConfigurationUpdateAction extends ActionType<ConfigurationUpdateResponse> {

    public static final ConfigurationUpdateAction INSTANCE = new ConfigurationUpdateAction();

    public static final String ACTION_NAME = "cluster:admin/security/config/update";

    public ConfigurationUpdateAction() {
        super(ACTION_NAME, ConfigurationUpdateResponse::new);
    }
}
