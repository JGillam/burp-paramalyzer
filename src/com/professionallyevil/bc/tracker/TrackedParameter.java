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

import burp.IBurpExtenderCallbacks;
import com.professionallyevil.bc.CorrelatedParam;
import com.professionallyevil.bc.ParamInstance;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.SortedSet;

public class TrackedParameter {
    CorrelatedParam correlatedParam;
    Set<TrackedParameter> origins = new HashSet<>();
    ParamInstance.Format format;
    String paramTypeName;
    ValueQueueMap<String, ParamInstance> valueMap = new ValueQueueMap<>(10);  // track most recently seen values
    java.util.List<ParamSign> signs = new java.util.ArrayList<>();

    public TrackedParameter(CorrelatedParam param) {
        this.correlatedParam = param;
        this.format = param.getBestFormat();
    }

    @Override
    public String toString() {
        return correlatedParam.getSample().getName();
    }

    public void initialize(IBurpExtenderCallbacks callbacks) {
        SortedSet<ParamInstance> paramInstances = correlatedParam.getParamInstances(true);
        for(ParamInstance param: paramInstances) {
            valueMap.put(param.getValue(), param);
            paramTypeName = param.getTypeName();
        }
        origins.clear();
    }

    public String getTypeName() {
        return correlatedParam.getSample().getTypeName();
    }

    public void identifyPresence(String response, TrackedParameter origin, ParamInstance pi){
        for(Iterator<String> valueIterator = valueMap.keys(); valueIterator.hasNext();) {
            String key = valueIterator.next();
            String decodedValue = valueMap.get(key).getDecodedValue();
            String value = valueMap.get(key).getValue();

            if (response.contains(value) || response.contains(decodedValue)) {
                if (!pi.getValue().equals(value) && !pi.getDecodedValue().equals(decodedValue)) {
                    origins.add(origin);
                    return;
                }
            }
        }
    }

    public Iterator<ParamInstance> paramInstanceIterator() {
        return valueMap.values();
    }

    public ParamInstance.Format getFormat() {
        return format;
    }

    public String getOrigin() {
        return correlatedParam.getOrigin();
    }


}
