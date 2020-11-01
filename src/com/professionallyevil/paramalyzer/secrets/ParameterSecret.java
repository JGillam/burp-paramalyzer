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

import burp.ICookie;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.professionallyevil.paramalyzer.CorrelatedParam;

import java.util.HashSet;
import java.util.Set;

public class ParameterSecret extends Secret{
    CorrelatedParam correlatedParam;
    String currentValue;
    Set<String> patterns = new HashSet<>();

    ParameterSecret(CorrelatedParam correlatedParam) {
        this.correlatedParam = correlatedParam;
    }

    @Override
    public String getName() {
        return correlatedParam.getSample().getName();
    }

    @Override
    public String getType() {
        return "Param ("+correlatedParam.getSample().getTypeName()+")";
    }

    @Override
    public String analyzeRequest(byte[] requestBytes, IRequestInfo requestInfo, SecretHelpers helpers) {

        byte paramType = correlatedParam.getSample().getType();
        for(IParameter param: requestInfo.getParameters()) {
            if(param.getName().equals(this.getName()) && param.getType()==paramType) {
                String newValue = param.getValue();
                if(!newValue.equals(currentValue)) {
                    patterns = helpers.generateValuePool(newValue, true);
                    currentValue = newValue;
                }
                return newValue;
            }
        }

        for (String pattern: patterns) {
            if(helpers.findStringInBytes(requestBytes, pattern, false, 0, requestBytes.length) > -1){
                return pattern;
            }
        }

        return null;
    }

    @Override
    public String analyzeResponse(byte[] responseBytes, IResponseInfo responseInfo, SecretHelpers helpers) {
        byte paramType = correlatedParam.getSample().getType();
        if (paramType == IParameter.PARAM_COOKIE) {
            for(ICookie cookie: responseInfo.getCookies()) {
                if(cookie.getName().equals(this.getName())){
                    String newValue = cookie.getValue();
                    if(!newValue.equals(currentValue)) {
                        patterns = helpers.generateValuePool(newValue, true);
                        currentValue = newValue;
                    }
                    return newValue;
                }
            }
        } else {
            for (String pattern : patterns) {
                if (helpers.findStringInBytes(responseBytes, pattern, false, 0, responseBytes.length) > -1) {
                    return pattern;
                }
            }
        }

        return null;
    }
}
