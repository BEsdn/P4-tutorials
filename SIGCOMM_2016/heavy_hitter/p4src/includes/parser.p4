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
 */

parser start {                 //parsing，开始调用parser工具。
    return parse_ethernet;     //当前处理的是以太网协议字段，调用处理以太网的parser
}

#define ETHERTYPE_IPV4 0x0800

header ethernet_t ethernet;     //Header实例化

parser parse_ethernet {         //处理以太网协议的parser
    extract(ethernet);          //extract，parser工具解析 格式为以太网的Header实例ethernet。
    return select(latest.etherType) {   //select，类似if-else逻辑判断，判断条件是以太网字段的长度，根据判断条件决定调用何种工具
        ETHERTYPE_IPV4 : parse_ipv4;    //latest.etherType:0x0800    则调用ipv4的parser
        default: ingress;               //latest.etherType属性不为0x0800   调用ingress结束解析
    }
}

header ipv4_t ipv4;

#define IP_PROTOCOLS_TCP 6

parser parse_ipv4 {             //处理ipv4协议的parser
    extract(ipv4);              //解析ipv4协议
    return select(latest.protocol) {
        IP_PROTOCOLS_TCP : parse_tcp;
        default: ingress;
    }
}

header tcp_t tcp;

parser parse_tcp {              //处理tcp协议的parser
    extract(tcp);               //解析tcp协议
    return ingress;             //调用ingress结束
}
