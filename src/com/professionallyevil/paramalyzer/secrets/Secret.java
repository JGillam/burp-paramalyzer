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

import java.util.ArrayList;
import java.util.List;

abstract class Secret {
    List<SecretResult> results = new ArrayList<>();

    abstract String getName();

    abstract String getType();

    abstract List<String> getValues(int max, boolean includeDecoded);

    abstract String getExampleValue();

    public void setResults(List<SecretResult> results) {
        this.results = results;
    }

    public List<SecretResult> getResults() {
        return this.results;
    }

    abstract boolean huntHashedValues();

    abstract void setHuntHashedValues(boolean huntHashedValues);

    public void clearResults(){
        results.clear();
    }
}
