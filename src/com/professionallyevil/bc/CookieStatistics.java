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

public class CookieStatistics {
    private String name;
    private int count = 0;
    private int httpOnlyCount = 0;
    private int secureCount = 0;

    public CookieStatistics(String name) {
        this.name = name;
    }

    void addCookieValues(boolean httpOnly, boolean secure) {
        count+=1;
        if(httpOnly) {
            httpOnlyCount += 1;
        }
        if(secure) {
            secureCount += 1;
        }
    }

    public String getName(){
        return this.name;
    }

    public int getCount() {
        return count;
    }

    public String getHttpOnly() {
        return httpOnlyCount==count?"Always":(httpOnlyCount==0?"Never":""+httpOnlyCount+"/"+count);
    }

    public String getSecure() {
        return secureCount==count?"Always":(secureCount==0?"Never":""+secureCount+"/"+count);
    }


}
