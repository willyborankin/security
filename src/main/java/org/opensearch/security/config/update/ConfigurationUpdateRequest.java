package org.opensearch.security.config.update;

import java.io.IOException;

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.master.AcknowledgedRequest;
import org.opensearch.core.common.io.stream.StreamInput;

public class ConfigurationUpdateRequest extends AcknowledgedRequest<ConfigurationUpdateRequest> {

    public ConfigurationUpdateRequest() {
        super();
    }

    public ConfigurationUpdateRequest(StreamInput in) throws IOException {
        super(in);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }
}
