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

import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ExecutionException;

/**
 * Created by jgillam on 4/19/2017.
 */
public class DeepAnalyzer extends SwingWorker<String, Object> {

    private ParamInstance pi;
    private List<CorrelatedParam> correlatedParams;
    private IBurpExtenderCallbacks callbacks;
    private WorkerStatusListener l;

    private Map<ParamInstance,String> resultsMap = new HashMap<>();

    protected DeepAnalyzer(ParamInstance pi, List<CorrelatedParam> correlatedParams, IBurpExtenderCallbacks callbacks, WorkerStatusListener listener) {
        this.pi = pi;
        this.correlatedParams = correlatedParams;
        this.callbacks = callbacks;
        this.l = listener;
    }

    @Override
    protected String doInBackground() throws Exception {
        publish(0);
        Map<String,Set<ParamInstance>> valueMap = generateValueMap(correlatedParams);

        switch (pi.getFormat()) {
            case MD5:
                processHash("MD5", valueMap);
                break;
            case SHA1:
                processHash("SHA-1", valueMap);
                break;
            case SHA256:
                processHash("SHA-256", valueMap);
                break;
            case NUMERIC:
                processNumeric(valueMap);
                break;
            default:
        }

        processMatches(valueMap);

        publish("Done.");
        return "";
    }


    // It may be worth considering caching this in the future, but for now tests show it is quite fast for processing 10,000 values.
    private Map<String,Set<ParamInstance>> generateValueMap(List<CorrelatedParam> correlatedParams){
        publish("Generating value map...");
        Map<String,Set<ParamInstance>> valueMap = new HashMap<>();
        int count = 1;
        for (CorrelatedParam correlatedParam: correlatedParams) {
            Set<ParamInstance> paramInstances = correlatedParam.getParamInstances(false);
            for (ParamInstance paramInstance: paramInstances) {
                String value = paramInstance.getValue();
                if (valueMap.containsKey(value)) {
                    valueMap.get(value).add(paramInstance);
                }else{
                    Set<ParamInstance> set = new HashSet<>();
                    set.add(paramInstance);
                    valueMap.put(value, set);
                }

                if (!paramInstance.getDecodedValue().equals(value)){
                    value = paramInstance.getDecodedValue();
                    if (valueMap.containsKey(value)) {
                        valueMap.get(value).add(paramInstance);
                    }else{
                        Set<ParamInstance> set = new HashSet<>();
                        set.add(paramInstance);
                        valueMap.put(value, set);
                    }
                }
            }
            publish((count++)/correlatedParams.size());
        }
        publish("Value map complete. "+valueMap.size()+" unique values mapped.");
        return valueMap;
    }

    private void processHash(String algorithm, Map<String,Set<ParamInstance>> valueMap) {
        String value = pi.getDecodedValue();
        byte[] valueBytes = ParamAnalyzer.hexStringToByteArray(value);

        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);

            int count = 1;
            for (String compareValue: valueMap.keySet()) {
                md.reset();
                md.update(compareValue.getBytes());
                byte[] digest = md.digest();
                if (MessageDigest.isEqual(digest, valueBytes)) {
                    addOrAppendResults(valueMap, compareValue, "The " + algorithm + " of this parameter value ("+compareValue+") resulted in" +
                            " the target value.");
                }
                publish((count++)/correlatedParams.size());
            }
        } catch (NoSuchAlgorithmException e) {
            callbacks.printError(e.getMessage());
        }
    }

    private void processNumeric(Map<String, Set<ParamInstance>> valueMap) {
        try {
            long longValue = Long.parseLong(pi.getDecodedValue());
            if(longValue > 0) {
                String base62Encoded = Base62.encode(longValue);
                for (String compareValue : valueMap.keySet()) {
                    if(compareValue.equals(base62Encoded)) {
                        addOrAppendResults(valueMap, compareValue, "This parameter is the same as the target value base62 encoded.");
                    }
                }
            }
        } catch (NumberFormatException e) {
            // skip
        }
    }

    private void processMatches(Map<String, Set<ParamInstance>> valueMap) {
        Map<String,String> matches = new HashMap();
        matches.put(pi.getValue(), "The value of this parameter matches the target value.");
        if(!pi.getDecodedValue().equals(pi.getValue())) {
            matches.put(pi.getDecodedValue(), "The value of this parameter matches the decoded target value.");
        }
        if(ParamAnalyzer.isBase62Encoded(pi.getDecodedValue())){
            try {
                matches.put(""+Base62.decode(pi.getDecodedValue()), "The value of this parameter matches the base62 decoded target value");
            } catch (Exception e) {
                // skip
            }
        }

        for(String match: matches.keySet()) {
            for (String compareValue: valueMap.keySet()) {
                if (compareValue.equals(match)) {
                    addOrAppendResults(valueMap, compareValue, matches.get(match));
                }
            }
        }
    }

    private void addOrAppendResults(Map<String, Set<ParamInstance>> valueMap, String value, String resultText) {
        for(ParamInstance paramInstance: valueMap.get(value)) {
            if(!paramInstance.equals(pi)) {
                addOrAppendResult(paramInstance, resultText);
            }
        }
    }

    private void addOrAppendResult(ParamInstance paramInstance, String resultText) {
        if(resultsMap.containsKey(paramInstance)) {
            String message = resultsMap.get(paramInstance)+"\n\n";
            resultsMap.put(paramInstance, message += resultText);
        }else {
            resultsMap.put(paramInstance, resultText+"\n\n"+paramInstance.describe());
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
                callbacks.printOutput(lastMessage);
            } else if (chunk instanceof Integer) {
                lastPercent = (Integer) chunk;
            }
        }

        if (lastMessage != null) {
            l.setStatus(lastMessage);
        }
        if (lastPercent > -1) {
            l.setProgress(lastPercent);
        }
    }

    @Override
    protected void done() {
        l.setStatus("Deep analysis complete.");
        l.setProgress(100);
        try {
            this.get();
            l.done();
        } catch (InterruptedException e) {
            e.printStackTrace();
            callbacks.printError(e.getMessage());
        } catch (ExecutionException e) {
            callbacks.printError(e.getMessage());
        }
    }

    public Map<ParamInstance, String> getResultsMap() {
        return resultsMap;
    }

}
