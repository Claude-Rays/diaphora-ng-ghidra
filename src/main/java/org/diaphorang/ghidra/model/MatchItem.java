/*
 * Diaphora, a binary diffing tool
 * Copyright (c) 2015-2026 Joxean Koret
 * Copyright (c) 2026 ClaudeMonkey (Java port, Claude-Rays/diaphora-ng-ghidra)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package org.diaphorang.ghidra.model;

import java.util.Objects;

/**
 * A matched pair of functions between Primary and Secondary programs.
 */
public class MatchItem {

    private String address1;
    private String name1;
    private String address2;
    private String name2;
    private String description;
    private double ratio;
    private int nodes1;
    private int nodes2;
    private String pseudo1;
    private String pseudo2;
    private String asm1;
    private String asm2;
    private String prototype1;
    private String prototype2;
    private String comment1;
    private String comment2;

    public MatchItem() {}

    public MatchItem(String address1, String name1, String address2, String name2,
                     String description, double ratio, int nodes1, int nodes2) {
        this.address1 = address1;
        this.name1 = name1;
        this.address2 = address2;
        this.name2 = name2;
        this.description = description;
        this.ratio = ratio;
        this.nodes1 = nodes1;
        this.nodes2 = nodes2;
    }

    public String getKey() {
        return (name1 != null ? name1 : "") + "-" + (name2 != null ? name2 : "");
    }

    public String getAddress1() {
        return address1;
    }

    public void setAddress1(String address1) {
        this.address1 = address1;
    }

    public String getName1() {
        return name1;
    }

    public void setName1(String name1) {
        this.name1 = name1;
    }

    public String getAddress2() {
        return address2;
    }

    public void setAddress2(String address2) {
        this.address2 = address2;
    }

    public String getName2() {
        return name2;
    }

    public void setName2(String name2) {
        this.name2 = name2;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public double getRatio() {
        return ratio;
    }

    public void setRatio(double ratio) {
        this.ratio = ratio;
    }

    public int getNodes1() {
        return nodes1;
    }

    public void setNodes1(int nodes1) {
        this.nodes1 = nodes1;
    }

    public int getNodes2() {
        return nodes2;
    }

    public void setNodes2(int nodes2) {
        this.nodes2 = nodes2;
    }

    public String getPseudo1() {
        return pseudo1;
    }

    public void setPseudo1(String pseudo1) {
        this.pseudo1 = pseudo1;
    }

    public String getPseudo2() {
        return pseudo2;
    }

    public void setPseudo2(String pseudo2) {
        this.pseudo2 = pseudo2;
    }

    public String getAsm1() {
        return asm1;
    }

    public void setAsm1(String asm1) {
        this.asm1 = asm1;
    }

    public String getAsm2() {
        return asm2;
    }

    public void setAsm2(String asm2) {
        this.asm2 = asm2;
    }

    public String getPrototype1() {
        return prototype1;
    }

    public void setPrototype1(String prototype1) {
        this.prototype1 = prototype1;
    }

    public String getPrototype2() {
        return prototype2;
    }

    public void setPrototype2(String prototype2) {
        this.prototype2 = prototype2;
    }

    public String getComment1() {
        return comment1;
    }

    public void setComment1(String comment1) {
        this.comment1 = comment1;
    }

    public String getComment2() {
        return comment2;
    }

    public void setComment2(String comment2) {
        this.comment2 = comment2;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MatchItem matchItem = (MatchItem) o;
        return Objects.equals(address1, matchItem.address1) && Objects.equals(address2, matchItem.address2);
    }

    @Override
    public int hashCode() {
        return Objects.hash(address1, address2);
    }
}
