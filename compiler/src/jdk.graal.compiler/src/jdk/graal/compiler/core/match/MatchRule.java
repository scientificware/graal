/*
 * Copyright (c) 2014, 2018, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package jdk.graal.compiler.core.match;

import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jdk.graal.compiler.nodes.ConstantNode;

/**
 * This annotation declares a textual pattern for matching an HIR tree. The format is a LISP style
 * s-expression with node types and/or names that are matched against the HIR. Node types are always
 * uppercase and the names of nodes are always lowercase. Named nodes can be used to match trees
 * where a node is used multiple times but only as an input to the full match.
 *
 * <pre>
 *   &lt;node-name&gt;    := [a-z][a-zA-Z0-9]*
 *   &lt;node-type&gt;    := [A-Z][a-zA-Z0-9]*
 *   &lt;node-spec&gt;    := &lt;node-type&gt; { '=' &lt;node-name&gt; }
 *   &lt;node-or-name&gt; := &lt;node-spec&gt; | &lt;node-name&gt;
 *   &lt;argument&gt;     := &lt;node-or-name&gt; | &lt;match-rule&gt;
 *   &lt;match-rule&gt;   := '(' &lt;node-spec&gt; &lt;argument&gt;+ ')'
 * </pre>
 *
 * All matched nodes except the root of the match and {@link ConstantNode}s must have a single user.
 * All matched nodes must be in the same block.
 */

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@Repeatable(value = MatchRules.class)
public @interface MatchRule {
    String value();
}