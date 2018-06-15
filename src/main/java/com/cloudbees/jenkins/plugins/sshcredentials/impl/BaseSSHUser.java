package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUser;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.api.resource.APIResource;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import org.apache.commons.lang.StringUtils;

/**
 * @author stephenc
 * @since 28/02/2012 13:44
 */
public class BaseSSHUser extends BaseStandardCredentials implements SSHUser, StandardUsernameCredentials {

    /**
     * Ensure consistent serialization.
     */
    private static final long serialVersionUID = 1L;

    /**
     * The username.
     */
    protected final String username;

    public BaseSSHUser(CredentialsScope scope, String id, String username, String description) {
        super(scope, id, description);
        this.username = username;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    public String getUsername() {
        return StringUtils.isEmpty(username) ? System.getProperty("user.name") : username;
    }

    @Override
    public APIResource getDataAPI() {
        return new Resource(this);
    }

    public static class Resource extends BaseStandardCredentials.Resource {

        private String username;

        public Resource() {}

        public Resource(BaseSSHUser model) {
            super(model);
            username = model.getUsername();
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }
    }
}
