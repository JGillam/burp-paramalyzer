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

import java.util.ArrayList;
import java.util.List;

public class CookieStatistics {
    private String name;
    private int count = 0;
    private int httpOnlyCount = 0;
    private int secureCount = 0;
    private String cookieType = "Session";
    private List<String> domainList = new ArrayList<>();
    private String domains = "(Never Set)";
    private List<String> pathList = new ArrayList<>();
    private String paths = "(Never Set)";

    public CookieStatistics(String name) {
        this.name = name;
    }

    void addCookieValues(boolean httpOnly, boolean secure, String expires, String maxAge, String domain, String path) {
        count+=1;
        if(httpOnly) {
            httpOnlyCount += 1;
        }
        if(secure) {
            secureCount += 1;
        }
        if (expires != null || maxAge != null) {
            cookieType = "Persistent";
        }
        if(domain != null && !domainList.contains(domain)) {
            domainList.add(domain);
            domains = String.join(",", domainList);
        }
        if(path != null && !pathList.contains(path)) {
            pathList.add(path);
            paths = String.join(",", pathList);
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

    String getType(){
        return cookieType;
    }

    String getDomains(){
        return domains;
    }

    String getPaths(){
        return paths;
    }


}
