/*
 * Copyright (c) 2019 Jason Gillam
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

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

class JSONParamParser {

    enum JSONValue {
        OBJECT("^\\{(\\s*\"([^\\\"^\\\\^\\p{Cntrl}]+)\"\\s*:(\\s*((-?\\d+)|(\"[^\\\"^\\\\^\\p{Cntrl}]*\")|true|false|null|\\[.*\\]|\\{.*\\})\\s*))(,\\s*\"([^\\\"^\\\\^\\p{Cntrl}]*)\"\\s*:(\\s*((-?\\d+)|(\"[^\\\"^\\\\^\\p{Cntrl}]*\")|true|false|null|\\[.*\\]|\\{.*\\})\\s*))*\\}$");


        private String regex;
        private Pattern pattern;

        JSONValue(String regex) {
            this.regex = regex;
            this.pattern = Pattern.compile(regex);
        }

        String getRegex(){
            return regex;
        }

        Pattern getPattern() {
            return pattern;
        }
    }

    private static void parseValue(List<JSONParamInstance> paramList, ParamInstance parent, String key, Object value) {
        if (value instanceof JSONObject) {
            parseObject((JSONObject)value, paramList, parent);
            paramList.add(new JSONParamInstance(key, value.toString(), parent));
        } else if (value instanceof JSONArray) {
            parseArray((JSONArray)value, key, paramList, parent);
            paramList.add(new JSONParamInstance(key, value.toString(), parent));
        } else if (value instanceof String) {
            paramList.add(new JSONParamInstance(key, (String)value, parent));
        } else if (value instanceof Integer) {
            try {
                paramList.add(new JSONParamInstance(key, Integer.toString((Integer)value), parent));
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else if (value instanceof Boolean) {
            paramList.add(new JSONParamInstance(key, Boolean.toString((Boolean)value), parent));
        }
    }

    private static void parseObject(JSONObject jsonObject, List<JSONParamInstance> paramList, ParamInstance parent) {
        for(String key: jsonObject.keySet()) {
            Object value = jsonObject.get(key);
            parseValue(paramList, parent, key, value);
        }
    }

    private static void parseArray(JSONArray array, String key, List<JSONParamInstance> paramList, ParamInstance parent) {
        for(Object value: array) {
            parseValue(paramList, parent, key, value);
        }
    }

    static List<JSONParamInstance> parseObjectString(String jsonString, ParamInstance parent){
        List<JSONParamInstance> paramList = new ArrayList<>();

        try {
            JSONObject jo = new JSONObject(jsonString);
            parseObject(jo, paramList, parent);
        } catch (JSONException e) {
            // skip
        }

        return paramList;

    }

//    public static void main(String[] args) {
//        parseObjectString("{\"foo\":\"bar\"}");
//        parseObjectString("{\"foo\":-42}");
//        parseObjectString("{\"foo\":[\"foo bar\", -42]}");
//        parseObjectString("{\"foo\": true}");
//        parseObjectString("{\"foo\": null}");
//        parseObjectString("{\"foo\": {\"bar\": \"foo2\"}}");
//        parseObjectString("{\"foo\":\"bar\" ,\"foo2\":\"bar2\",\"foo3\":\"bar3\",\"foo4\":\"bar4\"}");
//        parseObjectString("not a json object");
//    }

}
