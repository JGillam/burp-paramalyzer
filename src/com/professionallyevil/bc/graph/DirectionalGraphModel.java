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

package com.professionallyevil.bc.graph;

import java.util.*;

public class DirectionalGraphModel<T> {

    Map<T, VertexInfo> vertices = new HashMap<>();  // Map of Vertex --> VertexInfo for instance
    Map<T, Set<T>> parentMap = new HashMap<>();  // Map of Vertex --> Set of Parent Vertices
    boolean modelHasChanged = false;
    List<List<T>> columns = new ArrayList<>();
    int largestColumnSize = 0;
    int rowGap = 20;
    int columnGap = 50;
    List<GraphModelListener> listeners = new ArrayList<>();

    public void addGraphModelListener(GraphModelListener l){
        listeners.add(l);
    }

    public void removeGraphModelListener(GraphModelListener l){
        listeners.remove(l);
    }

    void fireGraphModelUpdated() {
        for(GraphModelListener l:listeners) {
            planLayout();
            l.graphModelUpdated();
        }
    }

    public void addVertex(T vertex) {
        if (!vertices.containsKey(vertex)) {
            vertices.put(vertex, new VertexInfo());
            modelHasChanged = true;
            fireGraphModelUpdated();
        }
    }

    public void addEdge(T fromVertex, T toVertex) {
        if (!parentMap.containsKey(toVertex)) {
            parentMap.put(toVertex, new HashSet<T>());
        }
        parentMap.get(toVertex).add(fromVertex);

        addVertex(fromVertex);
        addVertex(toVertex);

        modelHasChanged = true;
        fireGraphModelUpdated();
    }

    public void clear() {
        vertices.clear();
        parentMap.clear();
        modelHasChanged = true;
        fireGraphModelUpdated();
    }

    boolean planLayout() {  //TODO: special layout when there are no edges
        if(modelHasChanged) {
            for (T vertex:vertices.keySet()) {
                vertices.get(vertex).reset();
            }
            calculateColumns();
            calculateColumns();  // possibly inefficient, but currently it needs to be called a second time

            columns.clear();
            largestColumnSize = 0;

            for (T vertex:vertices.keySet()) {
                int column = vertices.get(vertex).getColumn();
                while (columns.size() < column+1) {
                    columns.add(new ArrayList<>());
                }
                columns.get(column).add(vertex);
                largestColumnSize = Math.max(largestColumnSize, columns.get(column).size());
            }
            modelHasChanged = false;
            return true;
        }
        return false;
    }

    public List<List<T>> getColumns() {
        return columns;
    }

    private void calculateColumns() {
        for (T toVertex: parentMap.keySet()) {
            int col = 0;
            for (T parent : parentMap.get(toVertex)) {
                if (parent != toVertex) {
                    col = Math.max(col, vertices.get(parent).getColumn());
                }
            }
            vertices.get(toVertex).setColumn(col + 1);
        }
    }

    public void printModel() {
        planLayout();
        for (T key:vertices.keySet()) {
            System.out.println(key + ": " + vertices.get(key).getColumn());
        }
    }

    public Set<T> getVertices() {
        return vertices.keySet();
    }

    public static void main(String[] args) {
        DirectionalGraphModel<String> model = new DirectionalGraphModel<String>();
        model.addEdge("jupiter", "saturn");
        model.addEdge("hello", "world");
        model.addEdge("hello", "jupiter");
        model.addEdge("bye", "jupiter");
        model.addEdge("jupiter", "pluto");
        model.printModel();
    }
}
