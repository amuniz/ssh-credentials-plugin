/*
 * The MIT License
 *
 * Copyright 2014 Jesse Glick.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.cli.CreateCredentialsByXmlCommand;
import com.cloudbees.plugins.credentials.cli.ImportAllCredentialsAsJSONCommand;
import com.cloudbees.plugins.credentials.cli.ListCredentialsCommand;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import com.cloudbees.plugins.credentials.domains.DomainSpecification;
import com.cloudbees.plugins.credentials.domains.HostnameSpecification;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.FilePath;
import hudson.cli.CLICommandInvoker;
import hudson.model.Hudson;
import hudson.remoting.Callable;
import hudson.security.ACL;
import jenkins.model.Jenkins;
import jenkins.security.MasterToSlaveCallable;

import org.apache.tools.ant.filters.StringInputStream;
import org.junit.Test;

import static hudson.cli.CLICommandInvoker.Matcher.succeeded;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;


public class BasicSSHUserPrivateKeyTest {

    final static String TESTKEY_ID = "bc07f814-78bd-4b29-93d4-d25b93285f93";
    final static String TESTKEY_BEGIN = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAu1r+HHzmpybc4iwoP5+44FjvcaMkNEWeGQZlmPwLx70XW8+8";
    final static String TESTKEY_END = "sroT/IHW2jKMD0v8kKLUnKCZYzlw0By7+RvJ8lgzHB0D71f6EC1UWg==\n-----END RSA PRIVATE KEY-----";

    @Rule public JenkinsRule r = new JenkinsRule();

    @Test public void masterKeysOnSlave() throws Exception {
        FilePath keyfile = r.jenkins.getRootPath().child("key");
        keyfile.write("stuff", null);
        SSHUserPrivateKey key = new BasicSSHUserPrivateKey(CredentialsScope.SYSTEM, "mycreds", "git", new BasicSSHUserPrivateKey.FileOnMasterPrivateKeySource(keyfile.getRemote()), null, null);
        assertEquals("[stuff]", key.getPrivateKeys().toString());
        // TODO would be more interesting to use a Docker fixture to demonstrate that the file load is happening only from the master side
        assertEquals("[stuff]", r.createOnlineSlave().getChannel().call(new LoadPrivateKeys(key)));
    }
    private static class LoadPrivateKeys extends MasterToSlaveCallable<String,Exception> {
        private final SSHUserPrivateKey key;
        LoadPrivateKeys(SSHUserPrivateKey key) {
            this.key = key;
        }
        @Override public String call() throws Exception {
            return key.getPrivateKeys().toString();
        }
    }

    @LocalData
    @Test
    public void readOldCredentials() throws Exception {
        SSHUserPrivateKey supk = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentials(SSHUserPrivateKey.class, Hudson.getInstance(), ACL.SYSTEM,
                        (List<DomainRequirement>)null),
                CredentialsMatchers.withId(TESTKEY_ID));
        assertNotNull(supk);
        List<String> keyList = supk.getPrivateKeys();
        assertNotNull(keyList);
        assertEquals(keyList.size(), 1);
        String privateKey = keyList.get(0);
        assertNotNull(privateKey);
        assertTrue(privateKey.startsWith(TESTKEY_BEGIN));
        assertTrue(privateKey.endsWith(TESTKEY_END));
    }

    @Test
    public void cliSmokes() throws IOException {
        CredentialsStore store = null;
        SystemCredentialsProvider.getInstance().setDomainCredentialsMap(
                Collections.singletonMap(Domain.global(), Collections.<Credentials>emptyList()));
        for (CredentialsStore s : CredentialsProvider.lookupStores(Jenkins.getInstance())) {
            if (s.getProvider() instanceof SystemCredentialsProvider.ProviderImpl) {
                store = s;
                break;
            }
        }
        assertThat("The system credentials provider is enabled", store, notNullValue());
        Domain smokes = new Domain("smokes", "smoke test domain",
                Collections.<DomainSpecification>singletonList(new HostnameSpecification("smokes.example.com", null)));
        BasicSSHUserPrivateKey smokey =
                new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "smokes-id-1", "smoke testing",
                        new BasicSSHUserPrivateKey.FileOnMasterPrivateKeySource("/tmp/privateKeyFile"),
                        "smoke text", "private key file");
        BasicSSHUserPrivateKey smokey2 =
                new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "smokes-id-2", "smoke testing",
                        new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource("JLÑH676askd/&/(&klasdkkaśjhdlñkjsd//&()&%"),
                        "smoke text", "direct private key");
        BasicSSHUserPrivateKey smokey3 =
                new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "smokes-id-3", "smoke testing",
                        new BasicSSHUserPrivateKey.UsersPrivateKeySource(),
                        "smoke text", "Use system user .ssh keys");
        store.addDomain(smokes, smokey);
        store.addCredentials(smokes, smokey2);
        store.addCredentials(smokes, smokey3);
        CLICommandInvoker invoker = new CLICommandInvoker(r, new ListCredentialsCommand());
        CLICommandInvoker.Result result = invoker.invokeWithArgs("system::system::jenkins", "--json");
        System.out.println(result.stdout());
        assertThat(result, succeeded());

        // TODO: move to a resource file
        String input = "{\n" +
                "\t\"version\": \"1\",\n" +
                "\t\"data\": [{\n" +
                "\t\t\"type\": \"domainCredentials\",\n" +
                "\t\t\"domain\": {\n" +
                "\t\t\t\"type\": \"domain\",\n" +
                "\t\t\t\"name\": \"smokes\",\n" +
                "\t\t\t\"description\": \"smoke test domain\",\n" +
                "\t\t\t\"specifications\": [{\n" +
                "\t\t\t\t\"type\": \"com.cloudbees.plugins.credentials.domains.HostnameSpecification$Resource\",\n" +
                "\t\t\t\t\"includes\": \"smokes.example.com\",\n" +
                "\t\t\t\t\"excludes\": null\n" +
                "\t\t\t}]\n" +
                "\t\t},\n" +
                "\t\t\"credentials\": [{\n" +
                "\t\t\t\"type\": \"com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey$Resource\",\n" +
                "\t\t\t\"scope\": \"GLOBAL\",\n" +
                "\t\t\t\"id\": \"smokes-id-4\",\n" +
                "\t\t\t\"description\": \"private key file\",\n" +
                "\t\t\t\"username\": \"smoke testing\",\n" +
                "\t\t\t\"privateKeyFileOnMaster\": \"/tmp/privateKeyFile\",\n" +
                "\t\t\t\"passphrase\": \"thepassphrase\"\n" +
                "\t\t}, {\n" +
                "\t\t\t\"type\": \"com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey$Resource\",\n" +
                "\t\t\t\"scope\": \"GLOBAL\",\n" +
                "\t\t\t\"id\": \"smokes-id-5\",\n" +
                "\t\t\t\"description\": \"direct private key\",\n" +
                "\t\t\t\"username\": \"smoke testing\",\n" +
                "\t\t\t\"privateKey\": \"ñaksjd79623ñlkasjd987lñakjsd\",\n" +
                "\t\t\t\"passphrase\": \"thepassphrase\"\n" +
                "\t\t}, {\n" +
                "\t\t\t\"type\": \"com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey$Resource\",\n" +
                "\t\t\t\"scope\": \"GLOBAL\",\n" +
                "\t\t\t\"id\": \"smokes-id-6\",\n" +
                "\t\t\t\"description\": \"Use system user .ssh keys\",\n" +
                "\t\t\t\"username\": \"smoke testing\",\n" +
                "\t\t\t\"userHomePrivateKey\": true,\n" +
                "\t\t\t\"passphrase\": \"thepassphrase\"\n" +
                "\t\t}]\n" +
                "\t}]\n" +
                "}";

        invoker = new CLICommandInvoker(r, new ImportAllCredentialsAsJSONCommand());
        result = invoker.withStdin(new StringInputStream(input)).invokeWithArgs("system::system::jenkins", "--json");
        System.out.println(result.stdout());
        assertThat(result, succeeded());
        assertThat(store.getCredentials(smokes), hasSize(6));
    }

    // TODO demonstrate that all private key sources are round-tripped in XStream

}
