package org.opensearch.security.dlic.rest.validation;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.security.dlic.rest.api.SecurityConfiguration;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

import static org.opensearch.security.dlic.rest.api.Responses.forbiddenMessage;
import static org.opensearch.security.dlic.rest.api.Responses.notFoundMessage;

public interface ConfigurationValidator {

    private String resourceName(final Endpoint endpoint) {
        switch (endpoint) {
            case ACCOUNT:
                return "account";
            case ACTIONGROUPS:
                return "actiongroup";
            case ALLOWLIST:
            case AUDIT:
            case CONFIG:
                return "config";
            case INTERNALUSERS:
                return "user";
            case NODESDN:
                return "nodesdn";
            case ROLES:
                return "role";
            case ROLESMAPPING:
                return "rolesmapping";
            case TENANTS:
                return "tenant";
            default:
                return "";
        }
    }

    private ValidationResult<SecurityConfiguration> isAllowedToChangeImmutableEntity(final SecurityConfiguration securityConfiguration)
            throws IOException {
        final var immutableCheck = entityImmutable(securityConfiguration);
        if (!immutableCheck.isValid() && !isCurrentUserAdmin()) {
            return immutableCheck;
        }
        return ValidationResult.success(securityConfiguration);
    }

    default ValidationResult<SecurityConfiguration> entityImmutable(final SecurityConfiguration securityConfiguration) throws IOException {
        return entityHidden(securityConfiguration).map(this::entityStatic).map(this::entityReserved);
    }

    default ValidationResult<SecurityConfiguration> entityStatic(final SecurityConfiguration securityConfiguration) {
        final var configuration = securityConfiguration.configuration();
        final var entityName = securityConfiguration.entityName();
        if (configuration.isStatic(entityName)) {

            return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Resource '" + entityName + "' is static."));
        }
        return ValidationResult.success(securityConfiguration);
    }

    default ValidationResult<SecurityConfiguration> entityReserved(final SecurityConfiguration securityConfiguration) {
        final var configuration = securityConfiguration.configuration();
        final var entityName = securityConfiguration.entityName();
        if (configuration.isReserved(entityName)) {
            return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Resource '" + entityName + "' is reserved."));
        }
        return ValidationResult.success(securityConfiguration);
    }

    default ValidationResult<SecurityConfiguration> entityHidden(final SecurityConfiguration securityConfiguration) {
        final var configuration = securityConfiguration.configuration();
        final var entityName = securityConfiguration.entityName();
        if (configuration.isHidden(entityName)) {
            return ValidationResult.error(RestStatus.NOT_FOUND, notFoundMessage("Resource '" + entityName + "' is not available."));
        }
        return ValidationResult.success(securityConfiguration);
    }

    default ValidationResult<SecurityConfiguration> entityExists(final SecurityConfiguration securityConfiguration) {
        return entityExists(resourceName(), securityConfiguration);
    }

    default ValidationResult<SecurityConfiguration> entityExists(
            final String resourceName,
            final SecurityConfiguration securityConfiguration
    ) {
        return securityConfiguration.maybeEntityName().<ValidationResult<SecurityConfiguration>>map(entityName -> {
            if (!securityConfiguration.entityExists()) {
                return ValidationResult.error(
                        RestStatus.NOT_FOUND,
                        notFoundMessage(resourceName + " '" + securityConfiguration.entityName() + "' not found.")
                );
            }
            return ValidationResult.success(securityConfiguration);
        }).orElseGet(() -> ValidationResult.success(securityConfiguration));
    }

    default ValidationResult<SecurityConfiguration> onConfigDelete(final SecurityConfiguration securityConfiguration) throws IOException {
        return isAllowedToChangeImmutableEntity(securityConfiguration).map(this::entityExists);
    }

    default ValidationResult<SecurityConfiguration> onConfigLoad(final SecurityConfiguration securityConfiguration) throws IOException {
        return null;//isAllowedToLoadOrChangeHiddenEntity(securityConfiguration).map(this::entityExists);
    }

    default ValidationResult<SecurityConfiguration> onConfigChange(final SecurityConfiguration securityConfiguration) throws IOException {
        return null;//isAllowedToChangeImmutableEntity(securityConfiguration);
    }


    ConfigurationValidator FORBIDDEN_VALIDATOR = new ConfigurationValidator() {
        @Override
        public ValidationResult<SecurityConfiguration> onConfigDelete(SecurityConfiguration securityConfiguration) throws IOException {
            return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Access denied"));
        }

        @Override
        public ValidationResult<SecurityConfiguration> onConfigLoad(SecurityConfiguration securityConfiguration) throws IOException {
            return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Access denied"));
        }

        @Override
        public ValidationResult<SecurityConfiguration> onConfigChange(SecurityConfiguration securityConfiguration) throws IOException {
            return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Access denied"));
        }
    };

    public static ConfigurationValidator of(final Endpoint endpoint) {
        if (endpoint == null) {
            return FORBIDDEN_VALIDATOR;
        } else {
            switch (endpoint) {
                default -> {
                    return FORBIDDEN_VALIDATOR;
                }
            }
        }
    }
}
