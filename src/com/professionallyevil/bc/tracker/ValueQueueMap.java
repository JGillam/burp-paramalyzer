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

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * A map that keeps track of the order of the most recently added items (by key). This is a non-blocking queue with a
 * capacity defined during construction. When an item is added after capacity, the head (i.e. least recently added item)
 * will be removed from the queue before adding the new item.  The associated key will be removed from the map as well.
 * The queue will replace the value for keys that are already in the queue.
 * The current implementation of this class should not be treated as thread-safe.
 *
 * @param <K> The keys for the Map, also the values in the queue.
 * @param <T> The type of the objects (values) referenced in the map.
 */
public class ValueQueueMap<K,T> {

    LinkedBlockingQueue<K> queue;
    Map<K, T> items;

    public ValueQueueMap(int capacity) {
        queue = new LinkedBlockingQueue<>(capacity);
        items = new HashMap<>(capacity);
    }

    public boolean put(K key, T value) {
        if (items.containsKey(key)) {
            items.put(key, value);
            queue.remove(key);
            return queue.offer(key);
        } else {
            if(queue.offer(key)) {
                items.put(key, value);
                return true;
            } else {
                K staleKey = queue.poll();
                if(staleKey != null) {
                    items.remove(staleKey);
                }
                if(queue.offer(key)) {
                    items.put(key, value);
                    return true;
                } else {
                    return false;
                }
            }
        }
    }

    public T get(K key) {
        return items.get(key);
    }

    /**
     *
     * @return keys in the queue order.
     */
    public Iterator<K> keys() {
        return queue.iterator();
    }

    // Just for testing/tinkering around with behavior.
    public static void main(String[] args) {

        ValueQueueMap<String, String> vqm = new ValueQueueMap<>(3);

        vqm.put("one", "value one");
        vqm.put("two", "value two");
        vqm.put("three", "value three");
        vqm.put("one", "value five");
        vqm.put("four", "value four");

        Iterator<String> stringIterator = vqm.keys();
        while(stringIterator.hasNext()) {
            String key = stringIterator.next();
            System.out.println(key + ": "+vqm.get(key));
        }

    }
}
