/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 */

package com.microsoft.azure.auth;

import com.microsoft.aad.adal4j.AdalErrorCode;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationException;
import com.microsoft.aad.adal4j.DeviceCode;
import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.credentials.AzureCliCredentials;
import com.microsoft.azure.credentials.AzureTokenCredentials;
import com.microsoft.azure.credentials.MSICredentials;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.http.client.utils.URIBuilder;
import org.slf4j.LoggerFactory;
import org.slf4j.spi.LocationAwareLogger;

import java.awt.Desktop;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutionException;

public class AzureAuthHelper {
    private static final String AUTH_WITH_OAUTH = "Authenticate with OAuth";
    private static final String AUTH_WITH_DEVICE_LOGIN = "Authenticate with Device Login";
    private static final Map<AzureEnvironment, String> AZURE_ENVIRONEMENT_NAMEMAP = new HashMap<>();

    static {
        final AzureEnvironment[] knownEnviroments = AzureEnvironment.knownEnvironments();

        for (final Field field : AzureEnvironment.class.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers())) {
                try {
                    final Object obj = FieldUtils.readStaticField(field);
                    if (ArrayUtils.contains(knownEnviroments, obj)) {
                        AZURE_ENVIRONEMENT_NAMEMAP.put((AzureEnvironment) obj, field.getName().toLowerCase());
                    }
                } catch (IllegalAccessException e) {
                    // ignore
                }

            }
        }
    }

    /**
     * Performs an OAuth 2.0 login.
     *
     * @param env the azure environment
     * @return the azure credential
     * @throws DesktopNotSupportedException when the desktop is not supported
     * @throws AzureLoginFailureException when there are some errors during login.
     * @throws ExecutionException if there are some errors acquiring security token.
     * @throws InterruptedException if the current thread was interrupted.
     */
    public static AzureCredential oAuthLogin(AzureEnvironment env)
            throws AzureLoginFailureException, ExecutionException, DesktopNotSupportedException, InterruptedException {
        if (!Desktop.isDesktopSupported() || !Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            throw new DesktopNotSupportedException("Not able to launch a browser to log you in.");
        }

        final LocalAuthServer server = new LocalAuthServer();
        try {
            server.start();
            final URI redirectUri = server.getURI();
            final String redirectUrl = redirectUri.toString();
            final String code;
            try {
                final String authorizationUrl = authorizationUrl(env, redirectUrl);
                Desktop.getDesktop().browse(new URL(authorizationUrl).toURI());
                System.out.println(AUTH_WITH_OAUTH);
                code = server.waitForCode();
            } catch (InterruptedException e) {
                throw new AzureLoginFailureException("The OAuth flow is interrupted.");
            } finally {
                server.stop();
            }
            final AzureCredential cred = new AzureContextExecutor(baseURL(env), context -> context
                    .acquireTokenByAuthorizationCode(code, env.managementEndpoint(), Constants.CLIENT_ID, redirectUri, null).get()).execute();
            cred.setEnvironment(getShortNameForAzureEnvironment(env));
            return cred;
        } catch (IOException | URISyntaxException e) {
            throw new AzureLoginFailureException(e.getMessage());
        }
    }

    /**
     * Performs a device login.
     *
     * @param env the azure environment
     * @return the azure credential through
     * @throws AzureLoginFailureException when there are some errors during login.
     * @throws ExecutionException if there are some errors acquiring security token.
     * @throws InterruptedException if the current thread was interrupted.
     * @throws MalformedURLException if there are some bad urls in azure endpoints
     */
    public static AzureCredential deviceLogin(AzureEnvironment env)
            throws AzureLoginFailureException, MalformedURLException, InterruptedException, ExecutionException {
        final String currentLogLevelFieldName = "currentLogLevel";
        Object logger = null;
        Object oldLevelValue = null;

        try {
            System.out.println(AUTH_WITH_DEVICE_LOGIN);

            try {
                // disable log4j of AuthenticationContext, otherwise the pending user
                // authorization log
                // will be print every second.
                // see
                // https://github.com/AzureAD/azure-activedirectory-library-for-java/issues/246
                logger = LoggerFactory.getLogger(AuthenticationContext.class);
                if (logger != null) {
                    oldLevelValue = FieldUtils.readField(logger, currentLogLevelFieldName, true);
                    FieldUtils.writeField(logger, currentLogLevelFieldName, LocationAwareLogger.ERROR_INT + 1, true);
                }
            } catch (IllegalArgumentException | IllegalAccessException e) {
                System.out.println("Failed to disable the log of AuthenticationContext, it will continue being noisy.");
            }
            final AzureCredential cred = new AzureContextExecutor(baseURL(env), authenticationContext -> {
                final DeviceCode deviceCode = authenticationContext.acquireDeviceCode(Constants.CLIENT_ID, env.activeDirectoryResourceId(), null).get();
                // print device code hint message:
                // to sign in, use a web browser to open the page
                // https://microsoft.com/devicelogin and enter the code xxxxxx to authenticate.
                System.out.println(TextUtils.yellow(deviceCode.getMessage()));
                long remaining = deviceCode.getExpiresIn();
                final long interval = deviceCode.getInterval();
                while (remaining > 0) {
                    try {
                        remaining -= interval;
                        Thread.sleep(Duration.ofSeconds(interval).toMillis());
                        return authenticationContext.acquireTokenByDeviceCode(deviceCode, null).get();
                    } catch (ExecutionException e) {
                        if (e.getCause() instanceof AuthenticationException &&
                                ((AuthenticationException) e.getCause()).getErrorCode() == AdalErrorCode.AUTHORIZATION_PENDING) {
                            // swallow the pending exception
                        } else {
                            // TODO: need to add a logger to the parameter
                            System.out.println(e.getMessage());
                            break;
                        }
                    }
                }
                throw new AzureLoginTimeoutException(
                        String.format("Cannot proceed with device login after waiting for %d minutes.", deviceCode.getExpiresIn() / 60));
            }).execute();
            cred.setEnvironment(getShortNameForAzureEnvironment(env));
            return cred;
        } finally {
            try {
                FieldUtils.writeField(logger, currentLogLevelFieldName, oldLevelValue, true);
            } catch (IllegalArgumentException | IllegalAccessException e) {
                // ignore
                System.out.println("Failed to reset the log level of AuthenticationContext.");
            }
        }

    }

    /**
     * Get azure credential from $HOME/.azure/azure-secret.json(created by `mvn azure:login`)
     *
     * @param env the azure environment
     * @return the saved azure credential
     * @throws IOException when there are some IO errors.
     */
    public static AzureTokenCredentials getMavenAzureLoginCredentials() throws IOException {
        final AzureCredential credentials = readAzureCredentials(getAzureSecretFile());
        final AzureEnvironment env = getAzureEnvironment(credentials.getEnvironment());
        return getMavenAzureLoginCredentials(credentials, env);
    }

    public static AzureTokenCredentials getMavenAzureLoginCredentials(AzureCredential credentials, AzureEnvironment env) throws IOException {
        final AzureTokenCredentials azureTokenCredentials = new AzureTokenCredentials(env, null) {
            @Override
            public String getToken(String resource) throws IOException {
                final String accessToken = credentials.getAccessToken();
                final String accessTokenWithoutSignature = accessToken.substring(0, accessToken.lastIndexOf('.') + 1);
                try {
                    final Jwt<?, Claims> c = Jwts.parser().parseClaimsJwt(accessTokenWithoutSignature);
                    // add 5 minutes to avoid the edge case of expired token right after checking
                    if (c.getBody().getExpiration().after(DateUtils.addMinutes(new Date(), 1))) {
                        return accessToken;
                    }
                } catch (ExpiredJwtException ex) {
                    // ignore
                }
                try {
                    final AzureCredential newCredentials = AzureAuthHelper.refreshToken(env, credentials.getRefreshToken());
                    credentials.setAccessToken(newCredentials.getAccessToken());
                    writeAzureCredentials(credentials, getAzureSecretFile());
                } catch (InterruptedException | ExecutionException e) {
                    throw new IOException(String.format("Error happened during refreshing access token, due to error: %s.", e.getMessage()));
                }

                return credentials.getAccessToken();
            }
        };
        if (StringUtils.isNotBlank(credentials.getDefaultSubscription())) {
            azureTokenCredentials.withDefaultSubscriptionId(credentials.getDefaultSubscription());
        }
        return azureTokenCredentials;
    }

    /**
     * Get an AzureTokenCredentials from : a. $HOME/.azure/azure-secret.json(created
     * by `mvn azure:login`) b. cloud shell c.
     * $HOME/.azure/azure-secret.json(created by `az login`)
     *
     * @param env the azure environment
     * @return the azure credential through
     * @throws IOException when there are some IO errors.
     */
    public static AzureTokenCredentials getAzureTokenCredentials() throws IOException {
        if (existsAzureSecretFile()) {
            try {
                return getMavenAzureLoginCredentials();
            } catch (IOException ex) {
                // ignore
            }
        }
        if (isInCloudShell()) {
            return new MSICredentials();
        }
        final File credentialParent = StringUtils.isBlank(System.getProperty(Constants.AZURE_HOME_KEY)) ?
                Paths.get(System.getProperty(Constants.USER_HOME_KEY), Constants.AZURE_HOME_DEFAULT).toFile() :
                new File(Constants.AZURE_HOME_KEY);
        if (credentialParent.exists() && credentialParent.isDirectory()) {
            final File azureProfile = new File(credentialParent, "azureProfile.json");
            final File accessTokens = new File(credentialParent, "accessTokens.json");

            if (azureProfile.exists() && accessTokens.exists()) {
                try {
                    final AzureCliCredentials azureCliCredentials = AzureCliCredentials.create(azureProfile, accessTokens);
                    if (azureCliCredentials.clientId() != null) {
                        return azureCliCredentials;
                    }

                } catch (IOException ex) {
                    // ignore
                }
            }
        }

        return null;
    }

    /**
     * Refresh an azure credential using refresh token.
     *
     * @param env          the azure environment
     * @param refreshToken the refresh token
     *
     * @return the azure credential
     * @throws AzureLoginFailureException when there are some errors during
     *                                    refreshing.
     */
    public static AzureCredential refreshToken(AzureEnvironment env, String refreshToken)
            throws MalformedURLException, InterruptedException, ExecutionException {
        if (env == null) {
            throw new IllegalArgumentException("Parameter 'env' cannot be null.");
        }
        if (StringUtils.isBlank(refreshToken)) {
            throw new IllegalArgumentException("Parameter 'refreshToken' cannot be empty.");
        }

        try {
            return new AzureContextExecutor(baseURL(env), authenticationContext -> authenticationContext
                    .acquireTokenByRefreshToken(refreshToken, Constants.CLIENT_ID, env.managementEndpoint(), null).get()).execute();
        } catch (AzureLoginTimeoutException e) {
            // ignore: it will never throw during refreshing
            return null;
        }

    }

    /**
     * Get the corresponding azure environment .
     *
     * @param environment the environment key
     * @return the AzureEnvironment instance
     */
    public static AzureEnvironment getAzureEnvironment(String environment) {
        if (StringUtils.isEmpty(environment)) {
            return AzureEnvironment.AZURE;
        }

        switch (environment.toUpperCase(Locale.ENGLISH)) {
            case "AZURE_CHINA":
                return AzureEnvironment.AZURE_CHINA;
            case "AZURE_GERMANY":
                return AzureEnvironment.AZURE_GERMANY;
            case "AZURE_US_GOVERNMENT":
                return AzureEnvironment.AZURE_US_GOVERNMENT;
            default:
                return AzureEnvironment.AZURE;
        }
    }

    /**
     * Get the azure-secret.json file according to environment variable, the default location is $HOME/.azure/azure-secret.json
     */
    public static File getAzureSecretFile() {
        return (StringUtils.isBlank(System.getProperty(Constants.AZURE_HOME_KEY)) ?
                Paths.get(System.getProperty(Constants.USER_HOME_KEY), Constants.AZURE_HOME_DEFAULT, Constants.AZURE_SECRET_FILE) :
                Paths.get(System.getProperty(Constants.AZURE_HOME_KEY), Constants.AZURE_SECRET_FILE)).toFile();
    }

    /**
     * Check whether the azure-secret.json file exists and is not empty.
     */
    public static boolean existsAzureSecretFile() {
        final File azureSecretFile = getAzureSecretFile();
        return azureSecretFile.exists() && azureSecretFile.isFile() && azureSecretFile.length() > 0;
    }

    /**
     * Delete the azure-secret.json.
     *
     * @return true if the file is deleted.
     */
    public static boolean deleteAzureSecretFile() {
        if (existsAzureSecretFile()) {
            return FileUtils.deleteQuietly(getAzureSecretFile());
        }
        return false;
    }

    /***
     * Save the credential to a file.
     *
     * @param cred the credential
     * @param file the file name to save the credential
     * @throws IOException if there is any IO error.
     */
    public static void writeAzureCredentials(AzureCredential cred, File file) throws IOException {
        if (cred == null) {
            throw new IllegalArgumentException("Parameter 'cred' cannot be null.");
        }
        if (file == null) {
            throw new IllegalArgumentException("Parameter 'file' cannot be null.");
        }
        FileUtils.writeStringToFile(file, JsonUtils.toJson(cred), "utf8");
    }

    /***
     * Read the credential from default location.
     *
     * @return the saved credential
     * @throws IOException if there is any IO error.
     */
    public static AzureCredential readAzureCredentials() throws IOException {
        return readAzureCredentials(getAzureSecretFile());
    }

    /***
     * Read the credential from a file.
     *
     * @param file the file to be read
     * @return the saved credential
     * @throws IOException if there is any IO error.
     */
    public static AzureCredential readAzureCredentials(File file) throws IOException {
        if (file == null) {
            throw new IllegalArgumentException("Parameter 'file' cannot be null.");
        }
        final String jsonStr = FileUtils.readFileToString(file, "utf8");
        return JsonUtils.fromJson(jsonStr, AzureCredential.class);
    }


    /**
     * Convert an AzureEnvironment instance to the short name, eg: azure, azure_china, azure_germany, azure_us_government.
     *
     * @param env the AzureEnvironment instance
     * @return the short name
     */
    public static String getShortNameForAzureEnvironment(AzureEnvironment env) {
        return AZURE_ENVIRONEMENT_NAMEMAP.get(env);
    }

    static boolean isInCloudShell() {
        return System.getenv(Constants.CLOUD_SHELL_ENV_KEY) != null;
    }

    static String authorizationUrl(AzureEnvironment env, String redirectUrl) throws URISyntaxException, MalformedURLException {
        if (env == null) {
            throw new IllegalArgumentException("Parameter 'env' cannot be null.");
        }
        if (StringUtils.isBlank(redirectUrl)) {
            throw new IllegalArgumentException("Parameter 'redirectUrl' cannot be empty.");
        }

        final URIBuilder builder = new URIBuilder(baseURL(env));
        builder.setPath(String.format("%s/oauth2/authorize", builder.getPath()))
            .setParameter("client_id", Constants.CLIENT_ID)
            .setParameter("response_type", "code")
            .setParameter("redirect_uri", redirectUrl)
            .setParameter("prompt", "select_account")
            .setParameter("resource", env.managementEndpoint());
        return builder.build().toURL().toString();
    }

    static String baseURL(AzureEnvironment env) {
        return env.activeDirectoryEndpoint() + Constants.COMMON_TENANT;
    }

    private AzureAuthHelper() {

    }
}
