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

import burp.IBurpExtenderCallbacks;
import com.professionallyevil.paramalyzer.ParamAnalyzer;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SecretHelpers{

    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
    IBurpExtenderCallbacks callbacks;
    List<MessageDigest> digests;

    public SecretHelpers(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        digests = new ArrayList<>();
        for (String algorithm : new String[]{"MD5", "SHA-1", "SHA-256"}) {
            try {
                digests.add(MessageDigest.getInstance(algorithm));
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
    }

    public Set<String> generateValuePool(String startingValue, boolean performMutations) {
        Set<String> valueSet = new HashSet<>();

        String inputString = startingValue;
        valueSet.add(inputString);
        String outputString = performDecoding(inputString);

        while(!outputString.equals(inputString)) {
            valueSet.add(outputString);
            inputString = outputString;
            outputString = performDecoding(inputString);
        }

        if(performMutations) {
            performMutations(startingValue, valueSet);
            if (!outputString.equals(startingValue)) {
                performMutations(outputString, valueSet);
            }
        }

        return valueSet;
    }

    private String performDecoding(String input) {
        if (ParamAnalyzer.ValuePattern.URL_ENCODED.matches(input)) {
            return callbacks.getHelpers().urlDecode(input);
        } else if (ParamAnalyzer.ValuePattern.BASE64_ENCODED.matches(input)) {
            byte[] decodedBytes = callbacks.getHelpers().base64Decode(input);
            return callbacks.getHelpers().bytesToString(decodedBytes);
        } else if (input.startsWith("\"") && input.endsWith("\"")) {
            return input.substring(1,input.lastIndexOf("\""));
        } else if(input.startsWith("'") && input.endsWith("'")) {
            return input.substring(1, input.lastIndexOf("'"));
        } else {
            return input;
        }
    }

    public  Set<String> performMutations(String startingValue) {
        return performMutations(startingValue, new HashSet<>());
    }

    public Set<String> performMutations(String startingValue, Set<String> valuePool) {
        String base64Encoded = callbacks.getHelpers().base64Encode(startingValue);
        valuePool.add(base64Encoded);
        valuePool.add(callbacks.getHelpers().urlEncode(base64Encoded));
        valuePool.add(callbacks.getHelpers().urlEncode(startingValue));

        for(MessageDigest digest: digests) {
            digest.reset();
            byte[] digestBytes = digest.digest(callbacks.getHelpers().stringToBytes(startingValue));
            String digestHex = bytesToHex(digestBytes);
            valuePool.add(digestHex);
            // TODO: should we include lower-case version of these hex strings as well?
        }
        return valuePool;
    }

    public static String bytesToHex(byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public int findStringInBytes(byte[] data, String pattern, boolean caseSensitive, int from, int to) {
        byte[] patternBytes = callbacks.getHelpers().stringToBytes(pattern);
        return callbacks.getHelpers().indexOf(data, patternBytes, caseSensitive, from, to);
    }

}
