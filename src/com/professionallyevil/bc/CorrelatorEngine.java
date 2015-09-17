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

import javax.swing.*;
import java.util.*;
import java.util.concurrent.ExecutionException;

public class CorrelatorEngine extends SwingWorker<String, Object> {
    IBurpExtenderCallbacks callbacks;
    CorrelatorEngineListener listener;
    boolean ignoreEmpty;
    Set<String> ignoreList = new HashSet<>();

    Map<String, CorrelatedParam> urlParameters = new HashMap<>();
    Map<String, CorrelatedParam> bodyParameters = new HashMap<>();
    Map<String, CorrelatedParam> cookieParameters = new HashMap<>();
    Set<IHttpRequestResponse> inScopeMessagesWithResponses = new HashSet<>();

    public CorrelatorEngine(IBurpExtenderCallbacks callbacks, CorrelatorEngineListener l, boolean ignoreEmpty, String ignoreThese) {
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

    private void firstPass(IExtensionHelpers helpers, IHttpRequestResponse[] messages) {
        publish("Examining parameters...");
        for (int i = 0; i < messages.length; i++) {
            publish(100 * i / messages.length);
            messages[i].getHttpService();
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
            }
        }
    }

    private void parameterFormatAnalysis() {
        publish("Parameter Format Analysis...");
        int total = urlParameters.size() + bodyParameters.size() + cookieParameters.size();
        int i=0;
        publish(0);
        for(CorrelatedParam cp: urlParameters.values()){
            cp.analyzeAll(callbacks);
            i+=1;
            publish(100*i/total);
        }
        for(CorrelatedParam cp: bodyParameters.values()){
            cp.analyzeAll(callbacks);
            i+=1;
            publish(100*i/total);
        }
        for(CorrelatedParam cp: cookieParameters.values()){
            cp.analyzeAll(callbacks);
            i+=1;
            publish(100*i/total);
        }
    }

    private void secondPass(IExtensionHelpers helpers) {
        publish("Second Pass...");
        publish(0);
        Set<Map<String, CorrelatedParam>> allStats = new HashSet<>();
        allStats.add(urlParameters);
        allStats.add(bodyParameters);
        allStats.add(cookieParameters);
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
            listener.done();
        } catch (InterruptedException e) {
            listener.setStatus("Interrupted Exception: " + e.getMessage());
        } catch (ExecutionException e) {
            listener.setStatus("Execution Exception: " + e.getMessage());
        } catch (Throwable e) {
            listener.setStatus(e.getMessage());
        }
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
}
