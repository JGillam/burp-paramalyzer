/*
 * Copyright (c) 2017 Jason Gillam
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

import javax.swing.*;
import java.io.PrintStream;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ExecutionException;

/**
 * This class manages the actual analysis of parameters in web traffic.  This is handled on a background thread so that
 * the UI can receive updates if it takes a while.
 */
public class CorrelatorEngine extends SwingWorker<String, Object> {
    IBurpExtenderCallbacks callbacks;
    WorkerStatusListener listener;
    boolean ignoreEmpty;
    Set<String> ignoreList = new HashSet<>();

    Map<String, CorrelatedParam> urlParameters = new HashMap<>();
    Map<String, CorrelatedParam> bodyParameters = new HashMap<>();
    Map<String, CorrelatedParam> cookieParameters = new HashMap<>();
    Map<String, CorrelatedParam> jsonParameters = new HashMap<>();
    Map<String, CorrelatedParam> restParameters = new HashMap<>();
    Map<String, CorrelatedParam> jsonPartParameters = new HashMap<>();
    Set<IHttpRequestResponse> inScopeMessagesWithResponses = new HashSet<>();
    Map<String, CookieStatistics> cookieStatistics = new TreeMap<>();

    public CorrelatorEngine(IBurpExtenderCallbacks callbacks, WorkerStatusListener l, boolean ignoreEmpty, String ignoreThese) {
        this.callbacks = callbacks;
        this.listener = l;
        this.ignoreEmpty = ignoreEmpty;
        String[] ignoreStrings = ignoreThese.split("\n");
        for(String s : ignoreStrings) {
            this.ignoreList.add(s.trim());
        }
    }

    @Override
    protected String doInBackground() throws Exception {
        publish("Starting...");
        IExtensionHelpers helpers = callbacks.getHelpers();
        publish(0);
        IHttpRequestResponse[] messages = callbacks.getProxyHistory();
        if (messages.length == 0) {
            publish(100);
        } else {
            firstPass(helpers, messages);
            parameterFormatAnalysis();
            //secondPass(helpers);  This is just too darn slow as it is now... need to rethink it.
        }
        return "";
    }

    /**
     * Analyze and categorize each of the parameters in scope.
     * @param helpers The standard burp ExtensionHelpers object.
     * @param messages The set of request messages to be processed.
     */
    private void firstPass(IExtensionHelpers helpers, IHttpRequestResponse[] messages) {
        publish("Examining parameters...");
        for (int i = 0; i < messages.length; i++) {
            publish(100 * i / messages.length);
            messages[i].getHttpService();
            //  Analyze response for cookies
            if(messages[i].getResponse() != null) {
                IResponseInfo responseInfo = helpers.analyzeResponse(messages[i].getResponse());
                List<String> headers = responseInfo.getHeaders();
                for (String header: headers){
                    if (startsWithIgnoreCase(header, "set-cookie:")) {
                        processCookieHeader(header);
                    }
                }
            }
            IRequestInfo requestInfo = helpers.analyzeRequest(messages[i]);
            if (callbacks.isInScope(requestInfo.getUrl())) {
                byte[] responseBytes = messages[i].getResponse();
                String responseString = "";
                if (responseBytes != null) {
                    responseString = helpers.bytesToString(responseBytes);
                    inScopeMessagesWithResponses.add(messages[i]);
                }

                List<IParameter> params = requestInfo.getParameters();
                for (IParameter param : params) {
                    if((!ignoreEmpty || param.getValue().length() > 0) && !ignoreList.contains(param.getName())) {
                        int type = param.getType();
                        Map<String, CorrelatedParam> paramMap;
                        switch (type) {
                            case IParameter.PARAM_URL:
                                paramMap = urlParameters;
                                break;
                            case IParameter.PARAM_BODY:
                                paramMap = bodyParameters;
                                break;
                            case IParameter.PARAM_COOKIE:
                                paramMap = cookieParameters;
                                break;
                            case IParameter.PARAM_JSON:
                                paramMap = jsonParameters;
                                break;
                            default:
                                paramMap = null;
                                // nothing
                        }

                        if (paramMap != null) {
                            if (messages[i] == null) {
                                callbacks.printOutput("Warning... adding null message!");
                            }

                            if (paramMap.containsKey(param.getName())) {
                                paramMap.get(param.getName()).put(param, messages[i], requestInfo, responseString,
                                        helpers);
                            } else {
                                paramMap.put(param.getName(), new CorrelatedParam(param, messages[i], requestInfo,
                                        responseString, helpers));
                            }
                        }
                    }
                }

                // look at path for REST variables
                URL url = requestInfo.getUrl();
                String[] pathElements = url.getPath().substring(1).split("/");

                for (int p=0; p < pathElements.length -1; p++){
                    RestParamInstance param = new RestParamInstance(pathElements[p], pathElements[p+1], messages[i]);

                    if (restParameters.containsKey(param.getName())) {
                        restParameters.get(param.getName()).put(param, messages[i], requestInfo, responseString,
                                helpers);
                    } else {
                        restParameters.put(param.getName(), new CorrelatedParam(param, messages[i], requestInfo,
                                responseString, helpers));
                    }
                }
            }
        }
    }

    private void parameterFormatAnalysis() {
        publish("Parameter Format Analysis...");
        int total = urlParameters.size() + bodyParameters.size() + cookieParameters.size() + jsonParameters.size() + restParameters.size();
        int i=0;
        publish(0);
        for(CorrelatedParam cp: urlParameters.values()){
            cp.analyzeAll(callbacks);
            processJSON(cp);
            i+=1;
            publish(100*i/total);
        }
        for(CorrelatedParam cp: bodyParameters.values()){
            cp.analyzeAll(callbacks);
            processJSON(cp);
            i+=1;
            publish(100*i/total);
        }
        for(CorrelatedParam cp: cookieParameters.values()){
            cp.analyzeAll(callbacks);
            processJSON(cp);
            i+=1;
            publish(100*i/total);
        }
        for(CorrelatedParam cp: jsonParameters.values()){
            cp.analyzeAll(callbacks);
            processJSON(cp);
            i+=1;
            publish(100*i/total);
        }
        for(CorrelatedParam cp: restParameters.values()){
            cp.analyzeAll(callbacks);
            processJSON(cp);
            i+=1;
            publish(100*i/total);
        }

        for(CorrelatedParam cp: jsonPartParameters.values()) {
            publish("Analyzing JSON params...");
            cp.analyzeAll(callbacks);
        }

        jsonParameters.putAll(jsonPartParameters);
    }

    private void processJSON(CorrelatedParam cp) {
        for(ParamInstance param: cp.uniqueParamInstances) {
            if(param.getFormat() == ParamInstance.Format.JSON) {
                List<JSONParamInstance> jsonParams = JSONParamParser.parseObjectString(param.decodedValue, param);
                for(JSONParamInstance jsonParam: jsonParams) {
                    if (jsonPartParameters.containsKey(jsonParam.getName())) {
                        jsonPartParameters.get(jsonParam.getName()).put(jsonParam);
                    } else {
                        jsonPartParameters.put(jsonParam.getName(), new CorrelatedParam(jsonParam));
                    }
                }
            }
        }
    }

    private void secondPass(IExtensionHelpers helpers) {
        publish("Second Pass...");
        publish(0);
        Set<Map<String, CorrelatedParam>> allStats = new HashSet<>();
        allStats.add(urlParameters);
        allStats.add(bodyParameters);
        allStats.add(cookieParameters);
        allStats.add(restParameters);
        int x = 0;
        for (IHttpRequestResponse message : inScopeMessagesWithResponses) {
            publish(100 * x / inScopeMessagesWithResponses.size());
            x += 1;
            String responseString = helpers.bytesToString(message.getResponse());
            for (Map<String, CorrelatedParam> paramMap : allStats) {
                for (String paramName : paramMap.keySet()) {
                    publish("Analyzing " + paramName + "...");
                    for (CorrelatedParam param : paramMap.values()) {
                        for (String value: param.getUniqueValues()) {
                            if (responseString.contains(value)) {
                                param.putSeenParam(value, message);
                            }
                        }
                    }
                }
            }
        }
    }

    @Override
    protected void process(List<Object> chunks) {
        super.process(chunks);
        String lastMessage = null;
        int lastPercent = -1;

        for (Object chunk : chunks) {
            if (chunk instanceof String) {
                lastMessage = (String) chunk;
            } else if (chunk instanceof Integer) {
                lastPercent = (Integer) chunk;
            }
        }

        if (lastMessage != null) {
            listener.setStatus(lastMessage);
        }
        if (lastPercent > -1) {
            listener.setProgress(lastPercent);
        }
    }

    @Override
    protected void done() {
        super.done();
        try {
            this.get();
            listener.done(null);
        } catch (InterruptedException e) {
            listener.setStatus("Interrupted Exception: " + e.getMessage());
            e.printStackTrace(new PrintStream(callbacks.getStderr()));
        } catch (ExecutionException e) {
            listener.setStatus("Execution Exception: " + e.getMessage());
            e.printStackTrace(new PrintStream(callbacks.getStderr()));
        } catch (Throwable e) {
            listener.setStatus(e.getMessage());
            e.printStackTrace(new PrintStream(callbacks.getStderr()));
        }
    }

    public static boolean startsWithIgnoreCase(String str, String prefix) {
        return str.regionMatches(true, 0, prefix, 0, prefix.length());
    }

    public void processCookieHeader(String header) {
        String[] parts = header.substring("set-cookie:".length()).split(";");
        boolean httpOnly = false;
        boolean secure = false;
        String expires = null;
        String maxAge = null;
        String domain = null;
        String path = null;
        String name = "";
        int count = 0;
        for (String part: parts) {
            String[] pair = part.split("=");
            String key = pair[0].trim().toUpperCase();
            switch(key) {
                case "HTTPONLY":
                    httpOnly = true;
                    break;
                case "SECURE":
                    secure = true;
                    break;
                case "EXPIRES":
                    expires = pair[1].trim();
                    break;
                case "MAX-AGE":
                    maxAge = pair[1].trim();
                    break;
                case "DOMAIN":
                    domain = pair[1].trim();
                    break;
                case "PATH":
                    path = pair[1].trim();
                    break;
                default:
                    // pass
            }
            if(count==0) {
                name = pair[0].trim();
            }
            count+=1;
        }
        if(!name.isEmpty()) {
            CookieStatistics cs;
            if (cookieStatistics.get(name) != null) {
                cs = cookieStatistics.get(name);
            } else {
                cs = new CookieStatistics(name);
                cookieStatistics.put(name, cs);
            }
            cs.addCookieValues(httpOnly, secure, expires, maxAge, domain, path);
        }

    }

    public Map<String, CookieStatistics> getCookieStatistics() {
        return cookieStatistics;
    }

    public Map<String, CorrelatedParam> getUrlParameters() {
        return urlParameters;
    }

    public Map<String, CorrelatedParam> getBodyParameters() {
        return bodyParameters;
    }

    public Map<String, CorrelatedParam> getCookieParameters() {
        return cookieParameters;
    }

    public Map<String, CorrelatedParam> getJSONParameters() { return jsonParameters; }

    public Map<String, CorrelatedParam> getRestParameters() {return restParameters; }
}
