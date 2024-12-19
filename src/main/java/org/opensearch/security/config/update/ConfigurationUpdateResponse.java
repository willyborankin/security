package org.opensearch.security.config.update;

import java.io.IOException;

import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

public class ConfigurationUpdateResponse extends AcknowledgedResponse {

    public ConfigurationUpdateResponse() {
        super(true);
    }

    public ConfigurationUpdateResponse(StreamInput in) throws IOException {
        super(in);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {}
}
