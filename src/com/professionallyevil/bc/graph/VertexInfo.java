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

public class VertexInfo {
    private int column = 0;
    private int x, y, width, height;


    public VertexInfo() {
    }

    public int getColumn() {
        return column;
    }

    public void setColumn(int column) {
        this.column = column;
    }

    public void reset(){
        column = 0;
    }

    public int getXRight() {
        return x + (width / 2);
    }

    public int getYRight() {
        return y;
    }


    public int getXLeft() {
        return x - (width / 2);
    }


    public int getYLeft() {
        return y;
    }

    public int getYTop() {
        return y - (height / 2);
    }

    public int getYBottom() {
        return y + (height / 2);
    }

    public int getXTop() {
        return x;
    }

    public int getXBottom() {
        return x;
    }


    public void setDimensions(int width, int height) {
        this.width = width;
        this.height = height;
    }

    /** This is the position of the center of the node. **/
    public void setPosition(int x, int y) {
        this.x = x;
        this.y = y;
    }
}
