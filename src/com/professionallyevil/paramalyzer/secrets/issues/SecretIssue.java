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

package com.professionallyevil.paramalyzer.secrets.issues;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import com.professionallyevil.paramalyzer.secrets.Secret;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

abstract class SecretIssue implements IScanIssue {

    URL url;
    IHttpService service;
    List<IHttpRequestResponse> messages = new ArrayList<>();
    String secretName;
    String secretType;

    public SecretIssue(URL url, IHttpService service, Secret secret) {
        this.url = url;
        this.service = service;
        this.secretName = secret.getName();
        this.secretType = secret.getType();
    }

    @Override
    public int getIssueType() {
        return  0x08000000;
    }

    @Override
    public URL getUrl() {
        return null;
    }

    @Override
    public IHttpService getHttpService() {
        return null;
    }

    String getSecretName() {
        return secretName;
    }

    String getSecretType() {
        return secretType;
    }

    public void addMessage(IHttpRequestResponse message) {
        messages.add(message);
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        IHttpRequestResponse[] messageArray = new IHttpRequestResponse[messages.size()];
        return messages.toArray(messageArray);
    }
}
