#!/bin/sh
#
# Generate the key SK which identifies  properties of destination node by the cpabe-keygen algorithm

cpabe-keygen -o SK_DST PK MK \
EC2 China Xen small \
'security = 2' \
'trust = 2'
