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

import burp.*;

import java.util.ArrayList;
import java.util.List;

public class SessionTestCase {

    private IParameter param;
    private String testcaseHeader;
    private int responseSize = 0;
    private String responseCode;



    byte[] testRequest;
    byte[] testResponse;

    SessionTestCase(){
    }

    SessionTestCase(IParameter param){
        this.param = param;
    }

    SessionTestCase(String header){
        this.testcaseHeader = header.substring(0, header.indexOf(":"));;
    }


    String getName() {
        if (param == null) {
            if (testcaseHeader != null) {
                return testcaseHeader;
            } else {
                return "***baseline***";
            }
        } else {
            return param.getName();
        }
    }

    String getType() {
        if (param == null) {
            if (testcaseHeader != null) {
                return "Header";
            } else {
                return "";
            }
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
        return param == null && testcaseHeader == null;
    }

    byte[] generateTestRequest(byte[] baseline, IBurpExtenderCallbacks callbacks) {
        if (param != null){
            IExtensionHelpers helpers = callbacks.getHelpers();
            switch(param.getType()) {
                default:
                    testRequest = helpers.removeParameter(baseline, param);
            }
        } else if (testcaseHeader != null) {
            IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(baseline);
            List<String> originalHeaders = requestInfo.getHeaders();
            List<String> newHeaders = new ArrayList<>(originalHeaders.size() - 1);
            for (String header: originalHeaders) {
                if (!header.startsWith(testcaseHeader)) {
                    newHeaders.add(header);
                }
            }
            byte[] body = new byte[baseline.length - requestInfo.getBodyOffset()];
            System.arraycopy(baseline, requestInfo.getBodyOffset(), body, 0, body.length);
            byte[] newRequest = callbacks.getHelpers().buildHttpMessage(newHeaders, body);
            callbacks.printOutput(new String(newRequest));
            testRequest = newRequest;

        } else {
            testRequest = baseline;
        }
        return testRequest;

    }

    public byte[] getTestRequest() {
        return testRequest;
    }


    public byte[] getTestResponse() {
        return testResponse;
    }


    public void analyzeResults(IResponseInfo responseInfo, byte[] response) {
        responseSize = response.length - responseInfo.getBodyOffset();
        responseCode = Short.toString(responseInfo.getStatusCode());
        testResponse = response;
    }
}
