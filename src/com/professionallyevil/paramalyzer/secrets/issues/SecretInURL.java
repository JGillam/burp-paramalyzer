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

import burp.IHttpService;
import com.professionallyevil.paramalyzer.secrets.Secret;

import java.net.URL;

public class SecretInURL extends SecretIssue {

    private String secretValue;

    public SecretInURL(URL url, IHttpService service, Secret secret, String value){
        super(url, service, secret);
        this.secretValue = value;
    }

    @Override
    public String getIssueName() {
        return "Secret in URL";
    }

    @Override
    public String getSeverity() {
        return "Medium";
    }

    @Override
    public String getConfidence() {
        return "Firm";
    }

    @Override
    public String getIssueBackground() {
        return "A value that was marked as a secret has been found as part of a URL. URL strings are generally considered " +
                "to be unsafe locations for sensitive information because they tend to surface in logs and may get inadvertently " +
                "sent to third party origins, for example, in a referer header. This may even happen when communication " +
                "occurs over HTTPS.";
    }

    @Override
    public String getRemediationBackground() {
        return "This type of issue can be verified by first determining if the identified value is truly considered sensitive. " +
                "If so, then this is a case of potential sensitive information exposure. However, there are use-cases that " +
                "may allow an exception. For example, there is now known way to avoid exposing the token in a password reset " +
                "link that is emailed to a user.";
    }

    @Override
    public String getIssueDetail() {
        return "A secret identified as <b>"+getSecretName()+"</b> with a value of <b>"+secretValue+"</b> was found in " +
                "the URL of the following request: "+getUrl().toString()+"<br>This may leak sensitive data to logs or " +
                "through referer headers.";
    }

    @Override
    public String getRemediationDetail() {
        return "Validate whether or not <b>"+getSecretName()+"</b> truly contains sensitive data. If so, the value should " +
                "be moved to a different part of the request, such as in a POST body. If this is not possible due to the " +
                "particular use-case (such as a password reset token), then the risk of exposure can be reduced by setting " +
                "a short lifespan/expiration for the value.";
    }

}
