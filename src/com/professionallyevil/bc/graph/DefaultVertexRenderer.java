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

import java.awt.*;

public class DefaultVertexRenderer<T> implements VertexRenderer<T>{

    int xInset = 5;
    int yInset = 5;

    public DefaultVertexRenderer() {

    }

    @Override
    public String getText(T vertexObject) {
        return vertexObject.toString();
    }

    @Override
    public int getWidth(T vertexObject, Graphics g) {
        return g.getFontMetrics().stringWidth(getText(vertexObject)) + (xInset * 2);
    }

    @Override
    public int getHeight(T vertexObject, Graphics g) {
        return g.getFontMetrics().getHeight() + (yInset * 2);
    }

    @Override
    public void render(T vertexObject, Graphics g, VertexInfo info, boolean isFocus) {
        if(isFocus) {
            g.setColor(Color.blue);
        } else {
            g.setColor(Color.black);
        }
        int x = info.getXCenter() - (getWidth(vertexObject, g) / 2);
        int y = info.getYCenter() - (getHeight(vertexObject, g) / 2);
        g.drawRect(x, y, getWidth(vertexObject, g), getHeight(vertexObject, g));

        g.drawString(vertexObject.toString(), x + xInset, y + yInset + g.getFontMetrics().getHeight());

    }
}
