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

package com.professionallyevil.bc.tracker;

import burp.*;
import com.professionallyevil.bc.WorkerStatusListener;

import javax.swing.*;
import java.util.*;
import java.util.concurrent.ExecutionException;

public class ParamTrackingHunter extends SwingWorker<Set<ParamTrackerEdge>, Object> {
    Set<TrackedParameter> secrets;
    IBurpExtenderCallbacks callbacks;
    WorkerStatusListener listener;

    ParamTrackingHunter(Set<TrackedParameter> secrets, IBurpExtenderCallbacks callbacks, WorkerStatusListener listener) {
        this.secrets = secrets;
        this.callbacks = callbacks;
        this.listener = listener;
        this.callbacks.printOutput("Hunter constructed!");
    }

    public Map<ParamKey, Set<TrackedParameter>> generateValuePatternMap() {
        Map<ParamKey, Set<TrackedParameter>> trackerValueMap = new HashMap<>();
        for (TrackedParameter secret: secrets) {
            for (Iterator<String> it = secret.valueMap.keys(); it.hasNext(); ) {
                String value = it.next();
                ParamKey key = new ParamKey(value, callbacks.getHelpers().stringToBytes(value));
                if (!trackerValueMap.containsKey(key)) {
                    trackerValueMap.put(key, new HashSet<TrackedParameter>());
                }
                trackerValueMap.get(key).add(secret);
            }
        }

        return trackerValueMap;

        // TODO: switch to this if we need to use patterns instead of Burp's internal search
//        Map<Pattern, Set<TrackedParameter>> valuePatternMap = new HashMap<>(trackerValueMap.size());
//        for (String key: trackerValueMap.keySet()) {
//            valuePatternMap.put(Pattern.compile(key, Pattern.CASE_INSENSITIVE & Pattern.LITERAL), trackerValueMap.get(key));
//        }
    }


    @Override
    protected Set<ParamTrackerEdge> doInBackground() throws Exception {
        callbacks.printOutput("doInBackground called...");
        publish(0);
        publish("Generating value map...");
        Map<ParamKey, Set<TrackedParameter>> trackerValueMap = generateValuePatternMap();

//        long startTime = System.currentTimeMillis();  //TODO: show an Estimate Remaining Time
        IHttpRequestResponse[] messages = callbacks.getProxyHistory();
        IExtensionHelpers helpers = callbacks.getHelpers();

        int progress = 0;
        int count = 0;
        publish("Analyzing proxy history of "+ messages.length+" message...");

            for (IHttpRequestResponse message : messages) {
                byte[] response = message.getResponse();
                if(response != null) {
                    for (ParamKey key : trackerValueMap.keySet()) {
                        int index = helpers.indexOf(response, key.getBytes(), false, 0, response.length - 1);
                        if (index > -1) {
                            IRequestInfo requestInfo = helpers.analyzeRequest(message.getRequest());
//                        URL url = requestInfo.getUrl();
                            IResponseInfo responseInfo = helpers.analyzeResponse(response);
                            byte[] responseBody = Arrays.copyOfRange(response, responseInfo.getBodyOffset(), response.length);
                            int responseHashcode = helpers.bytesToString(responseBody).hashCode();
                            // TODO: request hashcode is hardcoded. Should be calculated.
                            // TODO: url is not available
                            ParamSign sign = new ParamSign(count, index, key.getKeyName(), 0, responseHashcode, "");
                            for (TrackedParameter param : trackerValueMap.get(key)) {
                                param.addSign(sign);
                            }
                        }
                    }
                }

                // update progress
                count += 1;
                int percentDone = 100 * count / messages.length;
                if (percentDone > progress) {
                    publish(percentDone);
                    progress = percentDone;
                }

            }

        publish("Finding edges...");
        Set<ParamTrackerEdge> allEdges = new HashSet<>();
        for(TrackedParameter secret: secrets) {
            secret.clearEdges();
        }

        for(TrackedParameter responseSecret: secrets) {
                for (ParamSign sign: responseSecret.getSigns()) {
                    ParamKey paramKey = new ParamKey(sign.signValue, helpers.stringToBytes(sign.signValue));
                    for (TrackedParameter requestSecret: trackerValueMap.get(paramKey)) {
                        ParamTrackerEdge edge = new ParamTrackerEdge(requestSecret, responseSecret, sign);
                        allEdges.add(edge);
                        responseSecret.addEdge(edge);
                    }
                }
        }

        return allEdges;
    }

    @Override
    protected void process(List<Object> chunks) {
        for (Object chunk: chunks) {
            if (chunk instanceof Integer) {
                listener.setProgress((int)chunk);
            } else if (chunk instanceof String) {
                listener.setStatus((String)chunk);
            }
        }
    }

    @Override
    protected void done() {
        try {
            listener.done(get());
        } catch (InterruptedException | ExecutionException e) {
            callbacks.printError(e.getMessage());
            e.printStackTrace();
        }
    }

    class ParamKey{
        private String keyName;
        private byte[] bytes;

        ParamKey(String name, byte[] bytes){
            this.keyName = name;
            this.bytes = bytes;
        }

        public String getKeyName() {
            return keyName;
        }

        public byte[] getBytes() {
            return bytes;
        }

        @Override
        public boolean equals(Object obj) {
            if(obj instanceof ParamKey) {
                return ((ParamKey) obj).keyName.equals(this.keyName);
            } else {
                return false;
            }
        }

        @Override
        public int hashCode() {
            return keyName.hashCode() + 42;
        }
    }
}
