/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 */

package com.microsoft.azure.auth;

import com.microsoft.azure.AzureEnvironment;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class WebAppServerTest {
    private WebAppServer webAppServer;

    @Before
    public void setUp() throws Exception {
        webAppServer = new WebAppServer();
        webAppServer.start();
    }

    @After
    public void tearDown() throws Exception {
        webAppServer.stop();
    }

    @Test
    public void testOAuth() throws Exception {
        AzureAuthHelper.oAuthLogin(AzureEnvironment.AZURE);
    }

    @Test
    public void testGetCode() throws Exception {
        final String url = webAppServer.getUrl();
        final String token = "test_token";
        final String queryString = String.format("code=%s&session_state=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx", token);
        final URLConnection conn = new URL(url + "?" + queryString).openConnection();
        final Runnable runnable = () -> {
            try {
                assertEquals(token, webAppServer.getResult());
            } catch (Exception e) {
                fail("Encounter an error: " + e.getMessage());
            }
        };
        final Thread t = new Thread(runnable);
        t.start();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            final String html = reader.lines().collect(Collectors.joining("\n"));
            assertTrue(html.contains("Login successfully"));
            assertEquals(token, webAppServer.getResult());
        }
    }

    @Test
    public void testErrorResult() throws Exception {
        final String url = webAppServer.getUrl();
        final String queryString = "error=access_denied&error_description=the+user+canceled+the+authentication";
        final URLConnection conn = new URL(url + "?" + queryString).openConnection();
        final Runnable runnable = () -> {
            try {
                webAppServer.getResult();
            } catch (AzureLoginFailureException ex) {
                // expect
            } catch (InterruptedException e) {
                fail("Should throw AzureLoginFailureException");
            }
        };
        final Thread t = new Thread(runnable);
        t.start();
        try {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                final String html = reader.lines().collect(Collectors.joining("\n"));
                assertTrue(html.contains("Login failed"));
            }
        } catch (Exception ex) {
            // ignore
        }
    }

    @Test
    public void testStart() {

        // should be able to rest
        webAppServer.stop();
        try {
            webAppServer.start();
            fail("Should fail on after start.");
        } catch (Exception ex) {

        }
    }

    @Test
    public void testStop() {
        webAppServer.stop();
        // should not throw exception on second stop
        webAppServer.stop();
    }

}
