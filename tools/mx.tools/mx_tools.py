#
# mx_tools.py - the GraalVM specific commands
#
# Copyright (c) 2018, 2018, Oracle and/or its affiliates. All rights reserved.
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This code is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 only, as
# published by the Free Software Foundation.  Oracle designates this
# particular file as subject to the "Classpath" exception as provided
# by Oracle in the LICENSE file that accompanied this code.
#
# This code is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# version 2 for more details (a copy is included in the LICENSE file that
# accompanied this code).
#
# You should have received a copy of the GNU General Public License version
# 2 along with this work; if not, write to the Free Software Foundation,
# Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
# or visit www.oracle.com if you need additional information or have any
# questions.
#

import os
from os.path import exists
import re

import mx

from mx_sigtest import sigtest
from mx_unittest import unittest
from mx_gate import Task
import mx_gate
import mx_unittest
import mx_benchmark
import mx_sdk_vm

import sys

if sys.version_info[0] < 3:
    from urlparse import urljoin
else:
    from urllib.parse import urljoin # pylint: disable=no-name-in-module


_suite = mx.suite('tools')

class JMHRunnerToolsBenchmarkSuite(mx_benchmark.JMHRunnerBenchmarkSuite):

    def name(self):
        return "tools"

    def group(self):
        return "Graal"

    def subgroup(self):
        return "tools"

    def extraVmArgs(self):
        return ['-XX:-UseJVMCIClassLoader'] + super(JMHRunnerToolsBenchmarkSuite, self).extraVmArgs()

mx_benchmark.add_bm_suite(JMHRunnerToolsBenchmarkSuite())


def javadoc(args):
    """build the Javadoc for all packages"""
    if not args:
        projectNames = []
        for p in mx.projects(True, True):
            projectNames.append(p.name)
        mx.javadoc(['--unified', '--disallow-all-warnings', '--projects', ','.join(projectNames)], includeDeps=False)
    else:
        mx.javadoc(['--unified'] + args)
    javadocDir = os.sep.join([_suite.dir, 'javadoc'])
    index = os.sep.join([javadocDir, 'index.html'])
    if exists(index):
        indexContent = open(index, 'r').read()
        new_file = open(index, "w")
        new_file.write(indexContent)
    checkLinks(javadocDir)

def checkLinks(javadocDir):
    href = re.compile('(?<=href=").*?(?=")')
    filesToCheck = {}
    for root, _, files in os.walk(javadocDir):
        for f in files:
            if f.endswith('.html'):
                html = os.path.join(root, f)
                content = open(html, 'r').read()
                for url in href.findall(content):
                    full = urljoin(html, url)
                    sectionIndex = full.find('#')
                    questionIndex = full.find('?')
                    minIndex = sectionIndex
                    if minIndex < 0:
                        minIndex = len(full)
                    if 0 <= questionIndex < minIndex:
                        minIndex = questionIndex
                    path = full[0:minIndex]

                    sectionNames = filesToCheck.get(path, [])
                    if sectionIndex >= 0:
                        s = full[sectionIndex + 1:]
                        sectionNames = sectionNames + [(html, s)]
                    else:
                        sectionNames = sectionNames + [(html, None)]

                    filesToCheck[path] = sectionNames

    err = False
    for referencedfile, sections in filesToCheck.items():
        if referencedfile.startswith('javascript:') or referencedfile.startswith('http:') or referencedfile.startswith('https:') or referencedfile.startswith('mailto:'):
            continue
        if not exists(referencedfile):
            mx.warn('Referenced file ' + referencedfile + ' does not exist. Referenced from ' + sections[0][0])
            err = True
        else:
            content = open(referencedfile, 'r').read()
            for path, s in sections:
                if not s is None:
                    s = s.replace("%3C", "&lt;")
                    s = s.replace("%3E", "&gt;")
                    whereName = content.find('name="' + s + '"')
                    whereId = content.find('id="' + s + '"')
                    if whereName == -1 and whereId == -1:
                        mx.warn('There should be section ' + s + ' in ' + referencedfile + ". Referenced from " + path)
                        err = True

    if err:
        mx.abort('There are wrong references in Javadoc')

class ToolsUnittestConfig(mx_unittest.MxUnittestConfig):

    def __init__(self):
        super(ToolsUnittestConfig, self).__init__('tools')

    def apply(self, config):
        vmArgs, mainClass, mainClassArgs = config
        # This is required to access jdk.internal.module.Modules which
        # in turn allows us to dynamically open fields/methods to reflection.
        vmArgs = vmArgs + ['--add-exports=java.base/jdk.internal.module=ALL-UNNAMED']
        vmArgs = vmArgs + ['--add-modules=ALL-MODULE-PATH']
        # The tools unittests use internals
        mainClassArgs.extend(['-JUnitOpenPackages', 'com.oracle.truffle.tools.chromeinspector/*=ALL-UNNAMED'])
        mainClassArgs.extend(['-JUnitOpenPackages', 'com.oracle.truffle.tools.coverage/*=ALL-UNNAMED'])
        mainClassArgs.extend(['-JUnitOpenPackages', 'com.oracle.truffle.tools.dap/*=ALL-UNNAMED'])
        mainClassArgs.extend(['-JUnitOpenPackages', 'org.graalvm.tools.insight/*=ALL-UNNAMED'])
        mainClassArgs.extend(['-JUnitOpenPackages', 'org.graalvm.tools.insight.heap/*=ALL-UNNAMED'])
        mainClassArgs.extend(['-JUnitOpenPackages', 'org.graalvm.tools.lsp/*=ALL-UNNAMED'])
        return (vmArgs, mainClass, mainClassArgs)

mx_unittest.register_unittest_config(ToolsUnittestConfig())

def _tools_gate_runner(args, tasks):
    with Task('Tools Signature Tests', tasks) as t:
        if t: sigtest(['--check', 'binary'])
    with Task('Tools UnitTests', tasks) as t:
        if t: unittest(['--suite', 'tools', '--enable-timing', '--verbose', '--max-class-failures=25'])

mx_gate.add_gate_runner(_suite, _tools_gate_runner)

mx_sdk_vm.register_graalvm_component(mx_sdk_vm.GraalVmTool(
    suite=_suite,
    name='GraalVM Language Server',
    short_name='lsp',
    dir_name='lsp',
    license_files=[],
    third_party_license_files=[],
    dependencies=['Truffle JSON Library'],
    truffle_jars=['tools:LSP_API', 'tools:LSP'],
    support_distributions=['tools:LSP_GRAALVM_SUPPORT'],
    include_by_default=True,
))

mx_sdk_vm.register_graalvm_component(mx_sdk_vm.GraalVmTool(
    suite=_suite,
    name='GraalVM Debug Protocol Server',
    short_name='dap',
    dir_name='dap',
    license_files=[],
    third_party_license_files=[],
    dependencies=['Truffle JSON Library'],
    truffle_jars=['tools:DAP'],
    support_distributions=['tools:DAP_GRAALVM_SUPPORT'],
    include_by_default=True,
))

mx_sdk_vm.register_graalvm_component(mx_sdk_vm.GraalVmTool(
    suite=_suite,
    name='GraalVM Chrome Inspector',
    short_name='ins',
    dir_name='chromeinspector',
    license_files=[],
    third_party_license_files=[],
    dependencies=['Truffle JSON Library'],
    truffle_jars=['tools:CHROMEINSPECTOR'],
    support_distributions=['tools:CHROMEINSPECTOR_GRAALVM_SUPPORT'],
    include_by_default=True,
))

mx_sdk_vm.register_graalvm_component(mx_sdk_vm.GraalVmTool(
    suite=_suite,
    name='Insight',
    short_name='insight',
    dir_name='insight',
    license_files=[],
    third_party_license_files=[],
    dependencies=['Truffle'],
    truffle_jars=['tools:INSIGHT'],
    support_distributions=['tools:INSIGHT_GRAALVM_SUPPORT'],
    priority=10,
    include_by_default=True,
))

mx_sdk_vm.register_graalvm_component(mx_sdk_vm.GraalVmTool(
    suite=_suite,
    name='Insight Heap',
    short_name='insightheap',
    dir_name='insightheap',
    license_files=[],
    third_party_license_files=[],
    dependencies=['Truffle', 'insight'],
    truffle_jars=['tools:INSIGHT_HEAP'],
    support_distributions=['tools:INSIGHT_HEAP_GRAALVM_SUPPORT'],
    priority=10,
    include_by_default=True,
))

mx_sdk_vm.register_graalvm_component(mx_sdk_vm.GraalVmTool(
    suite=_suite,
    name='GraalVM Profiler',
    short_name='pro',
    dir_name='profiler',
    license_files=[],
    third_party_license_files=[],
    dependencies=['Truffle JSON Library'],
    truffle_jars=['tools:TRUFFLE_PROFILER'],
    support_distributions=['tools:TRUFFLE_PROFILER_GRAALVM_SUPPORT'],
    include_by_default=True,
))

mx_sdk_vm.register_graalvm_component(mx_sdk_vm.GraalVmTool(
    suite=_suite,
    name='GraalVM Coverage',
    short_name='cov',
    dir_name='coverage',
    license_files=[],
    third_party_license_files=[],
    dependencies=['Truffle JSON Library'],
    truffle_jars=['tools:TRUFFLE_COVERAGE'],
    support_distributions=['tools:TRUFFLE_COVERAGE_GRAALVM_SUPPORT'],
    include_by_default=True,
))

mx.update_commands(_suite, {
    'javadoc' : [javadoc, ''],
    'gate' : [mx_gate.gate, ''],
})
