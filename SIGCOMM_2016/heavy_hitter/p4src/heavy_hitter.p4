/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.


 
 *a)simple_router.p4定义的数据面中包换两条pipeline：ingress和egress。
 *b)ingress中有两级match-action，分别为ipv4_lpm和forward表。
 *c)egress中有一级match-action，send_frame表。
 *d)ipv4_lpm table中通过对下一跳IPv4地址(nhop_ipv4)进行最长前缀匹配(lpm)后修改下一跳地址(nhop_ipv4)或修改出端口(egress_port)。
 *e)forward table中通过对下一跳IPv4地址(nhop_ipv4)进行精确匹配(exact)后可以修改以太网帧的目的mac(dstAddr)或者将包丢弃(drop)。
 *f)send_frame table中通过对egress_port进行精确匹配后修改源mac地址(srcAddr)或将包丢弃。
 */

#include "includes/headers.p4"
#include "includes/parser.p4"

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

action _drop() {
    drop();
}

header_type custom_metadata_t {
    fields {
        nhop_ipv4: 32;
    }
}

metadata custom_metadata_t custom_metadata;

action set_nhop(nhop_ipv4, port) {
    modify_field(custom_metadata.nhop_ipv4, nhop_ipv4); //修改解析后表示中的包头字段值
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl, -1);
}

action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}

counter ip_src_counter {
    type: packets;
    static: count_table;
    instance_count: 1024;
}

action count_action(idx) {
    count(ip_src_counter, idx);
}

table count_table {
    reads {
        ipv4.srcAddr : lpm;
    }
    actions {
        count_action;
        _drop;
    }
    size : 1024;
}

table ipv4_lpm {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        set_nhop;
        _drop;
    }
    size: 1024;
}

table forward {
    reads {
        custom_metadata.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
        _drop;
    }
    size: 512;
}

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}

control ingress {
    apply(count_table);
    apply(ipv4_lpm);
    apply(forward);
}

control egress {
    apply(send_frame);
}
