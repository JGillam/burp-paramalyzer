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

import java.util.regex.Pattern;

public class CustomSecret extends Secret{
    private String name;
    private String exactMatch;
    private boolean isRegex = false;
    private Pattern pattern;

    CustomSecret(String name, boolean isRegex, String matchPattern) {
        this.name = name;
        if (isRegex) {
            pattern = Pattern.compile(matchPattern);
        } else {
            this.exactMatch = matchPattern;
        }
        this.isRegex = isRegex;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getType() {
        return isRegex?"Custom Regex":"Custom Match";
    }

    boolean isRegex() {
        return isRegex;
    }

    String getMatchString() {
        if(isRegex) {
            return pattern.pattern();
        } else {
            return exactMatch;
        }
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setRegex(String regexPattern) {
        pattern = Pattern.compile(regexPattern);
        isRegex = true;
    }

    public void setExactMatch(String matchString) {
        exactMatch = matchString;
        isRegex = false;
    }

    @Override
    public String analyzeRequest(byte[] requestBytes, IRequestInfo requestInfo, SecretHelpers helpers) {
        return null;
    }

    @Override
    public String analyzeResponse(byte[] responseBytes, IResponseInfo responseInfo, SecretHelpers helpers) {
        return null;
    }
}
