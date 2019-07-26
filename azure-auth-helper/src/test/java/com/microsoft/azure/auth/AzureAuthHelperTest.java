/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 */

package com.microsoft.azure.auth;

import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.azure.AzureEnvironment;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.junit.Test;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class AzureAuthHelperTest {

    @Test
    public void testOAuthLogin() throws Exception {
    }

    @Test
    public void testDeviceLogin() throws Exception {
    }

    @Test
    public void testRefreshTokenInvalidToken() throws Exception {
        try {
            AzureAuthHelper.refreshToken(AzureEnvironment.AZURE, "invalid");
            fail("Should throw ExecutionException when refreshToken is invalid.");
        } catch (ExecutionException e) {
            // ignore
            System.out.println(e.getCause().getClass().getName());
        }
    }

    @Test
    public void testRefreshTokenInvalidParameter() throws Exception {
        try {
            AzureAuthHelper.refreshToken(null, "abc");
            fail("Should throw IAE when env is null.");
        } catch (IllegalArgumentException e) {
            // ignore
        }

        try {
            AzureAuthHelper.refreshToken(AzureEnvironment.AZURE_CHINA, "");
            fail("Should throw IAE when refreshToken is empty.");
        } catch (IllegalArgumentException e) {
            // ignore
        }
    }

    @Test
    public void testGetAzureEnvironment() {
        assertEquals(AzureEnvironment.AZURE, AzureAuthHelper.getAzureEnvironment(null));
        assertEquals(AzureEnvironment.AZURE, AzureAuthHelper.getAzureEnvironment(""));
        assertEquals(AzureEnvironment.AZURE, AzureAuthHelper.getAzureEnvironment("invalid key"));

        assertEquals(AzureEnvironment.AZURE_CHINA, AzureAuthHelper.getAzureEnvironment("AZURE_CHINA"));
        assertEquals(AzureEnvironment.AZURE_CHINA, AzureAuthHelper.getAzureEnvironment("azure_china"));

        assertEquals(AzureEnvironment.AZURE_GERMANY, AzureAuthHelper.getAzureEnvironment("AZURE_GERMANY"));
        assertEquals(AzureEnvironment.AZURE_GERMANY, AzureAuthHelper.getAzureEnvironment("azure_germany"));

        assertEquals(AzureEnvironment.AZURE_US_GOVERNMENT, AzureAuthHelper.getAzureEnvironment("AZURE_US_GOVERNMENT"));
        assertEquals(AzureEnvironment.AZURE_US_GOVERNMENT, AzureAuthHelper.getAzureEnvironment("azure_us_government"));
    }

    @Test
    public void tetGetAzureSecretFile() throws Exception {
        File azureSecretFile = AzureAuthHelper.getAzureSecretFile();
        assertEquals(Paths.get(System.getProperty(Constants.USER_HOME_KEY), ".azure", "azure-secret.json").toString(),
                azureSecretFile.getAbsolutePath());
        System.setProperty(Constants.AZURE_HOME_KEY, "test_dir");
        azureSecretFile = AzureAuthHelper.getAzureSecretFile();
        assertEquals(Paths.get("test_dir", "azure-secret.json").toFile().getAbsolutePath(),
                azureSecretFile.getAbsolutePath());
    }

    @Test
    public void testReadWriteAzureCredentials() throws Exception {
        final File tempFile = File.createTempFile("azure-auth-helper", "unit-test");
        tempFile.deleteOnExit();
        final String authJson = "{\n" +
                "    \"accessTokenType\": \"Bearer\",\n" +
                "    \"idToken\": \"eyJ0eXAi...iOiIxLjAifQ.\",\n" +
                "    \"userInfo\": {\n" +
                "        \"uniqueId\": \"daaaa...3f2\",\n" +
                "        \"displayableId\": \"george@microsoft.com\",\n" +
                "        \"givenName\": \"George\",\n" +
                "        \"familyName\": \"Smith\",\n" +
                "        \"tenantId\": \"72f988bf-86f1-41af-91ab-2d7cd011db47\"\n" +
                "    },\n" +
                "    \"accessToken\": \"eyJ0eXA...jmcnxMnQ\",\n" +
                "    \"refreshToken\": \"AQAB...n5cgAA\",\n" +
                "    \"isMultipleResourceRefreshToken\": true\n" +
                "}";
        final AuthenticationResult result = JsonUtils.fromJson(authJson, AuthenticationResult.class);
        final AzureCredential cred = AzureCredential.fromAuthenticationResult(result);
        AzureAuthHelper.writeAzureCredentials(cred, tempFile);
        AzureCredential credentialFromFile = AzureAuthHelper.readAzureCredentials(tempFile);

        assertEquals(cred.isMultipleResourceRefreshToken(), credentialFromFile.isMultipleResourceRefreshToken());
        assertEquals(cred.getAccessTokenType(), credentialFromFile.getAccessTokenType());
        assertEquals(cred.getAccessToken(), credentialFromFile.getAccessToken());
        assertEquals(cred.getRefreshToken(), credentialFromFile.getRefreshToken());
        assertEquals(cred.getIdToken(), credentialFromFile.getIdToken());
        assertEquals(cred.getUserInfo().getFamilyName(), credentialFromFile.getUserInfo().getFamilyName());

        // second read should not throw exception
        credentialFromFile = AzureAuthHelper.readAzureCredentials(tempFile);
        final Map<String, Object> map = JsonUtils.fromJson(authJson, Map.class);
        assertEquals(map.get("accessTokenType"), credentialFromFile.getAccessTokenType());
        assertEquals(map.get("accessToken"), credentialFromFile.getAccessToken());
        assertEquals(map.get("refreshToken"), credentialFromFile.getRefreshToken());
        assertEquals(map.get("idToken"), credentialFromFile.getIdToken());
        assertEquals(map.get("isMultipleResourceRefreshToken"), credentialFromFile.isMultipleResourceRefreshToken());

        assertEquals("daaaa...3f2", credentialFromFile.getUserInfo().getUniqueId());
        assertEquals("george@microsoft.com", credentialFromFile.getUserInfo().getDisplayableId());
        assertEquals("George", credentialFromFile.getUserInfo().getGivenName());
        assertEquals("Smith", credentialFromFile.getUserInfo().getFamilyName());
    }

    @Test
    public void testAuthorizationUrl() throws Exception {
        String url = AzureAuthHelper.authorizationUrl(AzureEnvironment.AZURE, "http://localhost:4663");
        Map<String, String> queryMap = splitQuery(url);
        assertEquals(Constants.CLIENT_ID, queryMap.get("client_id"));
        assertEquals("http://localhost:4663", queryMap.get("redirect_uri"));
        assertEquals("code", queryMap.get("response_type"));
        assertEquals("select_account", queryMap.get("prompt"));
        assertEquals(AzureEnvironment.AZURE.activeDirectoryResourceId(), queryMap.get("resource"));

        url = AzureAuthHelper.authorizationUrl(AzureEnvironment.AZURE_CHINA, "http://localhost:4664");
        queryMap = splitQuery(url);
        assertEquals(Constants.CLIENT_ID, queryMap.get("client_id"));
        assertEquals("http://localhost:4664", queryMap.get("redirect_uri"));
        assertEquals("code", queryMap.get("response_type"));
        assertEquals("select_account", queryMap.get("prompt"));
        assertEquals(AzureEnvironment.AZURE_CHINA.activeDirectoryResourceId(), queryMap.get("resource"));
    }

    @Test
    public void tesAuthorizationUrlInvalidParameter() throws Exception {
        try {
            AzureAuthHelper.authorizationUrl(null, "http://localhost:4663");
            fail("Should throw IAE when env is null.");
        } catch (IllegalArgumentException e) {
            // ignore
        }

        try {
            AzureAuthHelper.authorizationUrl(AzureEnvironment.AZURE_CHINA, "");
            fail("Should throw IAE when redirectUrl is empty.");
        } catch (IllegalArgumentException e) {
            // ignore
        }
    }

    @Test
    public void testBaseURL() {
        String baseUrl = AzureAuthHelper.baseURL(AzureEnvironment.AZURE);
        assertEquals("https://login.microsoftonline.com/common", baseUrl);
        baseUrl = AzureAuthHelper.baseURL(AzureEnvironment.AZURE_US_GOVERNMENT);
        assertEquals("https://login.microsoftonline.us/common", baseUrl);
    }

    private static Map<String, String> splitQuery(String url) throws UnsupportedEncodingException, MalformedURLException {
        final Map<String, String> queryMap = new LinkedHashMap<>();
        final List<NameValuePair> params = URLEncodedUtils.parse(new URL(url).getQuery(), Constants.UTF8);
        for (final NameValuePair param : params) {
            queryMap.put(param.getName(), param.getValue());
        }

        return queryMap;
    }

}
