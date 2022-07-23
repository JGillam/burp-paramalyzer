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

import java.util.*;

public class ParameterSecret extends Secret{
    CorrelatedParam correlatedParam;

    boolean huntHashedValues;

    ParameterSecret(CorrelatedParam correlatedParam) {
        this.correlatedParam = correlatedParam;
        String name = correlatedParam.getSample().getName().toLowerCase();

        // Guess if this is a non-hashed password that we want to hunt hashed equivalents.
        ParamInstance.Format format = correlatedParam.getSample().getFormat();
        if("password passwd".contains(name) && format == ParamInstance.Format.PRINTABLE) {
            huntHashedValues = true;
        }
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
    List<String> getValues(int max, boolean includeDecoded) {
        Set<ParamInstance> instances = correlatedParam.getParamInstances(false);
        ArrayList<String> valueList = new ArrayList<>();
        for(Iterator<ParamInstance> instanceIterator = instances.iterator();instanceIterator.hasNext();) {
            ParamInstance instance = instanceIterator.next();
            String nextValue = instance.getValue();
            if(valueList.size()<max && !valueList.contains(nextValue)) {
                valueList.add(nextValue);
            }
            if(includeDecoded) {
                String decodedValue = instance.getDecodedValue();
                if (valueList.size()<max && !Objects.equals(decodedValue, nextValue)) {
                    valueList.add(decodedValue);
                }
            }
        }
        return valueList;
    }

    @Override
    String getExampleValue() {
        return correlatedParam.getParamInstances(false).first().getValue();
    }

    @Override
    public boolean huntHashedValues() {
        return huntHashedValues;
    }

    public void setHuntHashedValues(boolean huntHashedValues) {
        this.huntHashedValues = huntHashedValues;
    }

}
