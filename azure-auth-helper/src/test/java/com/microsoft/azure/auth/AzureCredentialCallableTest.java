/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 */

package com.microsoft.azure.auth;

import org.junit.Test;

import static org.junit.Assert.fail;

public class AzureCredentialCallableTest {

    @Test
    public void testConstructor() {
        new AzureCredentialCallable("test", a -> null);
    }

    @Test
    public void testConstructorInvalidParameter() {

        try {
            new AzureCredentialCallable(null, a -> null);
            fail("Should throw NPE when baseUrl is null.");
        } catch (NullPointerException e) {
            // ignore
        }

        try {
            new AzureCredentialCallable("", a -> null);
            fail("Should throw IAE when baseUrl is null.");
        } catch (IllegalArgumentException e) {
            // ignore
        }

        try {
            new AzureCredentialCallable("test", null);
            fail("Should throw IAE when acquireTokenFunc is null.");
        } catch (NullPointerException e) {
            // ignore
        }
    }
}
