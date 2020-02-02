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

public class ParamSign implements Comparable<ParamSign>{

    int signStart;
    int messageId;
    int requestHashcode;
    int responseHashcode;
    String url;  // the origin + path
    String signValue;

    public ParamSign(int messageId, int signStart, String signValue, int requestHashcode, int responseHashcode, String url) {
        this.messageId = messageId;
        this.signStart = signStart;
        this.signValue = signValue;
        this.requestHashcode = requestHashcode;
        this.responseHashcode = responseHashcode;
        this.url = url;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ParamSign) {
            return ((ParamSign) obj).compareTo(this) == 0;
        } else {
            return false;
        }
    }

    @Override
    public int compareTo(ParamSign o) {
        if(!signValue.equals(o.signValue)) {
            return signValue.compareTo(o.signValue);
        } else if (!url.equals(o.url)) {
            return url.compareTo(o.url);
        } else if(signStart != o.signStart) {
            return signStart > o.signStart? 1:-1;
        } else if(requestHashcode != o.requestHashcode) {
            return requestHashcode > o.requestHashcode? 1: -1;
        } else if(responseHashcode != o.responseHashcode) {
            return responseHashcode > o.responseHashcode? 1: -1;
        } else {
            return 0;
        }
    }

    // TODO:  Make this comparable, using the responseHash + signValue + url
}
