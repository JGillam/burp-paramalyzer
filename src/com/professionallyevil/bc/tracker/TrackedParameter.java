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

import java.util.SortedSet;

public class TrackedParameter {
    CorrelatedParam correlatedParam;
    ValueQueueMap<String, ParamInstance> values = new ValueQueueMap<>(10);

    public TrackedParameter(CorrelatedParam param) {
        this.correlatedParam = param;
    }

    @Override
    public String toString() {
        return correlatedParam.getSample().getName();
    }

    public void initialize(IBurpExtenderCallbacks callbacks) {
        SortedSet<ParamInstance> paramInstances = correlatedParam.getParamInstances(true);
        for(ParamInstance param: paramInstances) {
            values.put(param.getValue(), param);
        }
    }
}
