/*
 * Copyright (c) 2020 Jason Gillam
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.professionallyevil.paramalyzer.secrets;

import burp.IRequestInfo;
import burp.IResponseInfo;

/**
 * Abstract representation of a web application secret. Note that the storage of secret values is left to the implementation
 * since named parameters may change values over time. It is assumed that analysis will occur in chronological order in
 * request / response pairs (in that order).
 */
public abstract class Secret {

    public abstract String getName();

    public abstract String getType();

    /**
     * Analyze the given request to determine if this secret is present.
     * @param requestBytes The request bytes provided from the Burp Suite HTTP Message.
     * @param requestInfo The request info as provided by Burp Suite.
     * @param helpers The helpers singleton, in case it is needed.
     * @return The matching string, or null if no match is found.
     */
    public abstract String analyzeRequest(byte[] requestBytes, IRequestInfo requestInfo, SecretHelpers helpers);

    /**
     * Analyze the given response to determine if this secret is present.
     * @param responseBytes The response bytes provided by Burp Suite.
     * @param responsInfo The response info as provided by Burp Suite.
     * @param helpers The helpders singleton, in case it is needed.
     * @return The matching string, or null if no match is found.
     */
    public abstract String analyzeResponse(byte[] responseBytes, IResponseInfo responseInfo, SecretHelpers helpers);

}
