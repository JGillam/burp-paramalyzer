/*
 * Copyright (c) 2015 Jason Gillam
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

import java.util.*;

/**
 * This class represents a parameter in the web traffic.  It includes analysis of all instances of that parameter.
 */
public class CorrelatedParam {
    SortedSet<ParamInstance> paramInstances = new TreeSet<>();
    Set<String> uniqueURLs = new HashSet<>();
    Set<String> uniqueValues = new HashSet<>();
    SortedSet<ParamInstance> uniqueParamInstances = new TreeSet<>();
    int reflectedCount = 0;
    int decodedReflectedCount = 0;
    Map<String, IHttpRequestResponse> seenParams = new HashMap<>();
    Map<ParamInstance,String> analysisText = new HashMap<>();
    ParamInstance.Format bestFormat = ParamInstance.Format.UNKNOWN;
    int bestFormatPercent = 0;

    CorrelatedParam(IParameter param, IHttpRequestResponse message, IRequestInfo requestInfo, String responseString,
                    IExtensionHelpers helpers) {
        put(param, message, requestInfo, responseString, helpers);
    }


    public void put(IParameter param, IHttpRequestResponse message, IRequestInfo requestInfo, String responseString,
                    IExtensionHelpers helpers) {
        ParamInstance pi = new ParamInstance(param, message);
        paramInstances.add(pi);
        addURL(requestInfo);

        String value = param.getValue();
        if(!uniqueValues.contains(value)) {
            uniqueValues.add(value);
            uniqueParamInstances.add(pi);
        }
        checkReflection(param, responseString, helpers);
    }

    private void addURL(IRequestInfo requestInfo) {
        String externalForm = requestInfo.getUrl().toExternalForm();
        int paramStart = externalForm.indexOf('?');
        if (paramStart == -1) {
            uniqueURLs.add(externalForm);
        } else{
            uniqueURLs.add(externalForm.substring(0, paramStart));
        }
    }

    public void putSeenParam(String value, IHttpRequestResponse message) {
        seenParams.put(value, message);
    }

    public Set<String> getUniqueURLs() {
        return uniqueURLs;
    }

    public Set<String> getUniqueValues() {
        return uniqueValues;
    }

    private void checkReflection(IParameter param, String responseString, IExtensionHelpers helpers) {
        if(param.getValue().length()>2) {
            if (responseString.contains(param.getValue())) {
             reflectedCount += 1;
            }
            String decodedValue = helpers.urlDecode(param.getValue());
            if (!decodedValue.equals(param.getValue()) && responseString.contains(decodedValue)) {
                decodedReflectedCount += 1;
            }
        }
    }

    public int getReflectedCount() {
        return reflectedCount;
    }

    public int getDecodedReflectedCount() {
        return decodedReflectedCount;
    }

    public SortedSet<ParamInstance> getParamInstances(boolean withDuplicates) {
        return withDuplicates? this.paramInstances : this.uniqueParamInstances;
    }

    public Map<String, IHttpRequestResponse> getSeenParams() {
        return seenParams;
    }

    public ParamInstance getSample() {
        return paramInstances.first();
    }

    public String getAnalysisText(ParamInstance pi, IBurpExtenderCallbacks callbacks) {
        if(analysisText.containsKey(pi)) {
            return analysisText.get(pi);
        } else {
            String text = ParamAnalyzer.analyze(pi, callbacks);
            analysisText.put(pi, text);
            return text;
        }
    }

    public void analyzeAll(IBurpExtenderCallbacks callbacks){
        Map<ParamInstance.Format, Integer> formatCounts = new HashMap<>();

        for (ParamInstance pi: paramInstances) {
            getAnalysisText(pi, callbacks);
            ParamInstance.Format format = pi.getFormat();
            if (!format.equals(ParamInstance.Format.EMPTY)) {
                int count = formatCounts.containsKey(format) ? formatCounts.get(format) : 0;
                count += 1;
                formatCounts.put(format, count);
            }
        }

        ParamInstance.Format bestFormat = ParamInstance.Format.UNKNOWN;
        int bestCount = 0;
        int totalCount = 0;
        for(ParamInstance.Format format: formatCounts.keySet()) {
            int count = formatCounts.get(format);
            if(count > bestCount) {
                bestFormat = format;
                bestCount = count;
            }
            totalCount += count;
        }
        this.bestFormat = bestFormat;
        this.bestFormatPercent = totalCount > 0 ? 100 * bestCount / totalCount : 0;
    }

    public String getFormatString() {
        if(this.bestFormatPercent < 50 || bestFormat.equals(ParamInstance.Format.UNKNOWN)) {
            return ParamInstance.Format.UNKNOWN.getTitle();
        } else if(this.bestFormatPercent == 100) {
            return bestFormat.getTitle();
        } else {
            return bestFormat.getTitle() + " (" +bestFormatPercent+"%)";
        }
    }
}
