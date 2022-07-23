/*
 * Copyright (c) 2022 Jason Gillam
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

import burp.IHttpRequestResponse;

public class SecretResult {
    String value;
    String issueName;
    String severity; // "High", "Medium", "Low", "Information" or "False positive"

    String domain;
    IHttpRequestResponse requestResponse;
    boolean isResponse;
    int beginIndex;

    public SecretResult(String value, String issueName, String severity, IHttpRequestResponse requestResponse, String domain) {
        this.value = value;
        this.issueName = issueName;
        this.severity = severity;
        this.requestResponse = requestResponse;
        this.domain = domain;
    }

    public String getValue() {
        return value;
    }

    public String getIssueName() {
        return issueName;
    }

    public String getSeverity() {
        return severity;
    }

    public IHttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    public boolean isResponse() {
        return isResponse;
    }

    public int getBeginIndex() {
        return beginIndex;
    }

    public String getDomain(){
        return domain;
    }
}
