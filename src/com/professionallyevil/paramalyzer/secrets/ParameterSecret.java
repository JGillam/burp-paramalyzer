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

import com.professionallyevil.paramalyzer.CorrelatedParam;
import com.professionallyevil.paramalyzer.ParamInstance;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class ParameterSecret extends Secret{
    CorrelatedParam correlatedParam;

    ParameterSecret(CorrelatedParam correlatedParam) {
        this.correlatedParam = correlatedParam;
    }

    @Override
    String getName() {
        return correlatedParam.getSample().getName();
    }

    @Override
    String getType() {
        return "Param ("+correlatedParam.getSample().getTypeName()+")";
    }

    @Override
    List<String> getValues() {
        Set<ParamInstance> instances = correlatedParam.getParamInstances(false);
        ArrayList<String> valueList = new ArrayList<>();
        for(Iterator<ParamInstance> instanceIterator = instances.iterator();instanceIterator.hasNext();) {
            String nextValue = instanceIterator.next().getValue();
            if(valueList.size()<10 && !valueList.contains(nextValue)) {
                valueList.add(nextValue);
            }
        }
        return valueList;
    }
}
