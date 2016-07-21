#!/bin/sh
#
# Generate the key SK which identifies  properties of source node by the cpabe-keygen algorithm

cpabe-keygen -o SK_SRC PK MK \
'cpu_load = 2' \
'memory_utilization = 1'
