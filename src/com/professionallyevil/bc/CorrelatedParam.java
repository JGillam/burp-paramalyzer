/*
 * Copyright (c) 2019 Jason Gillam
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
    boolean isInteresting = false;
    Map<String, IHttpRequestResponse> seenParams = new HashMap<>();
    Map<ParamInstance,String> analysisText = new HashMap<>();
    ParamInstance.Format bestFormat = ParamInstance.Format.UNKNOWN;
    int bestFormatPercent = 0;
    private static String[] INTERESTING_HINTS = {"session","key","user","password","token","ssn"};
    private static String[] INTERESTING_BLACKLIST = {"true","false","0","1","null"};
    private static Set<String> blacklist = new HashSet<>();
    String origin;

    static {
        blacklist.addAll(Arrays.asList(INTERESTING_BLACKLIST));
    }

    CorrelatedParam(IParameter param, IHttpRequestResponse message, int msgNum, IRequestInfo requestInfo,  String responseString,
                    String origin, IExtensionHelpers helpers) {
        this.origin = origin;
        put(param, message, msgNum, requestInfo, responseString, helpers);
    }

    CorrelatedParam(RestParamInstance param, IHttpRequestResponse message, int msgNum, IRequestInfo requestInfo,  String responseString,
                    String origin, IExtensionHelpers helpers) {
        this.origin = origin;
        put(param, message, msgNum, requestInfo, responseString, helpers);
    }

    CorrelatedParam(JSONParamInstance param, String origin) {
        this.origin = origin;
        put(param);
    }

    public void put(IParameter param, IHttpRequestResponse message, int msgNum, IRequestInfo requestInfo, String responseString,
                    IExtensionHelpers helpers) {
        ParamInstance pi = new ParamInstance(param, message, msgNum);
        paramInstances.add(pi);
        addURL(requestInfo);

        String value = param.getValue();
        if(!uniqueValues.contains(value)) {
            uniqueValues.add(value);
            uniqueParamInstances.add(pi);
        }
        checkReflection(param, responseString, helpers);
    }

    public void put(RestParamInstance param, IHttpRequestResponse message, int msgNum, IRequestInfo requestInfo, String responseString,
                    IExtensionHelpers helpers) {
        paramInstances.add(param);
        addURL((requestInfo));
        String value = param.getValue();
        if(!uniqueValues.contains(value)) {
            uniqueValues.add(value);
            uniqueParamInstances.add(param);
        }
        checkReflection(param, responseString, helpers);
    }

    public void put(JSONParamInstance param) {
        paramInstances.add(param);
        String value = param.getValue();
        if(!uniqueValues.contains(value)) {
            uniqueValues.add(value);
            uniqueParamInstances.add(param);
        }
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

    public String getOrigin() {
        return this.origin;
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
            String decodedValue = helpers.urlDecode(param.getValue());
            if (responseString.contains(param.getValue())) {
             reflectedCount += 1;
            } else if (!decodedValue.equals(param.getValue()) && responseString.contains(decodedValue)) {
                reflectedCount += 1;
            }
        }
    }

    public int getReflectedCount() {
        return reflectedCount;
    }

    public boolean isInteresting() {
        return isInteresting;
    }

    public void setInteresting(boolean s) {
        isInteresting = s;
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
            String text = "";
            if (pi instanceof JSONParamInstance) {
                String logPrefix = "This parameter was derived from a JSON object: "+ ((JSONParamInstance)pi).getParent().getName()+"\n";
                text = ParamAnalyzer.analyze(pi, callbacks, logPrefix);
            } else {
                text = ParamAnalyzer.analyze(pi, callbacks);
            }

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

        if (bestFormat.isInteresting()){
            isInteresting = true;
        } else {
            for (String hint : INTERESTING_HINTS) {
                if (getSample().getName().toLowerCase().contains(hint) && !blacklist.contains(getSample().getValue().toLowerCase())) {
                    isInteresting = true;
                }
            }
        }
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
