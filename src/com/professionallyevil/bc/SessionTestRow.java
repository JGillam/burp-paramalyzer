/*
 * Copyright (c) 2018 Jason Gillam
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

package com.professionallyevil.bc;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IParameter;
import burp.IResponseInfo;

public class SessionTestRow {

    private IParameter param;
    private int responseSize = 0;
    private String responseCode;

    SessionTestRow(IParameter param){
        this.param = param;
    }

    String getName() {
        return param == null?"***baseline***":param.getName();
    }

    String getType() {
        if (param == null) {
            return "";
        } else {
            switch (param.getType()) {
                case IParameter.PARAM_COOKIE:
                    return "Cookie";
                default:
                    return "other";
            }
        }
    }

    int getResponseSize(){
        return responseSize;
    }

    String getResponseCode(){
        return responseCode;
    }

    boolean isBaseline() {
        return param == null;
    }

    byte[] generateTestRequest(byte[] baseline, IBurpExtenderCallbacks callbacks) {
        if (isBaseline()) {
            return baseline;
        } else {
            IExtensionHelpers helpers = callbacks.getHelpers();
            switch(param.getType()) {
                default:
                    return helpers.removeParameter(baseline, param);
            }

        }
    }

    public void analyzeResults(IResponseInfo responseInfo, byte[] response) {
        responseSize = response.length - responseInfo.getBodyOffset();
        responseCode = Short.toString(responseInfo.getStatusCode());
    }
}
