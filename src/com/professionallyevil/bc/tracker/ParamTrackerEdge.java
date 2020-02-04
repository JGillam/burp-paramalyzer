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

public class ParamTrackerEdge {
    enum Column {
        REQ_PARAM("Req. Param"),
        REQ_VALUE("Req. Value"),
        ORIGIN("Origin"),
        PATH("Path"),
        IN_SCOPE("In Scope"),
        RESP_PARAM("Resp. Param"),
        RESP_VALUE("Resp. Value");

        private final String title;

        Column(String title) {
            this.title = title;
        }

        public String getTitle(){
            return title;
        }

    }

    TrackedParameter requestSecret;
    TrackedParameter responseSecret;
    ParamSign sign;

    public ParamTrackerEdge(TrackedParameter requestSecret, TrackedParameter responseSecret, ParamSign sign) {
        this.requestSecret = requestSecret;
        this.responseSecret = responseSecret;
        this.sign = sign;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ParamTrackerEdge) {
            if (requestSecret == null) {
                return ((ParamTrackerEdge) obj).requestSecret == null &&
                        responseSecret.equals(((ParamTrackerEdge) obj).responseSecret) &&
                        sign.equals(((ParamTrackerEdge) obj).sign);
            } else {
                return ((ParamTrackerEdge) obj).requestSecret.equals(requestSecret) &&
                        responseSecret.equals(((ParamTrackerEdge) obj).responseSecret) &&
                        sign.equals(((ParamTrackerEdge) obj).sign);
            }
        } else {
            return false;
        }
    }

    public Object getValue(Column column) {
        switch (column) {
            case REQ_PARAM:
                return requestSecret == null ? "(None)" : requestSecret.toString();
            case REQ_VALUE:
                return  requestSecret == null ? "" : "???";
            case ORIGIN:
                return  requestSecret == null ? "" : "???";
            case PATH:
                return requestSecret == null ? "": "???";
            case IN_SCOPE:
                return "???";
            case RESP_PARAM:
                return responseSecret.toString();
            case RESP_VALUE:
                return sign.signValue;
            default:
                return "?";
        }
    }

}
