#! /usr/bin/python

from scapy import all
from scapy.all import *
import sys
import binascii

### PACKET TYPES ###

message_type = {
      2 : 'GetService',
      3 : 'StateService',
     12 : 'GetHostInfo',
     13 : 'StateHostInfo',
     14 : 'GetHostFirmware',
     15 : 'StateHostFirmware',
     16 : 'GetWifiInfo',
     17 : 'StateWifiInfo',
     18 : 'GetWifiFirmware',
     19 : 'StateWifiFirmware',
     20 : 'GetPower',
     21 : 'SetPower',
     22 : 'StatePower',
     23 : 'GetLabel',
     24 : 'SetLabel',
     25 : 'StateLabel',
     32 : 'GetVersion',
     33 : 'StateVersion',
     34 : 'GetInfo',
     35 : 'StateInfo',
     45 : 'Acknowledgement',
     48 : 'GetLocation',
     50 : 'StateLocation',
     51 : 'GetGroup',
     53 : 'StateGroup',
     58 : 'EchoRequest',
     59 : 'EchoResponse',
    101 : 'Get',
    102 : 'SetColor',
    107 : 'State',
    116 : 'GetPower',
    117 : 'SetPower',
    118 : 'StatePower',
    }

### FIELDS ###

class LifxLenField(LEShortField):
    def i2m(self, pkt, x):
        if x is None:
            x = 8 + len(pkt.payload) # TODO: must this be hardcoded?
        return x

### HEADERS ###

class Lifx_Frame (Packet):
    name = "Lifx Frame"
    fields_desc = [
                    LifxLenField("size", None),
                    BitField("origin", 0, 2),
                    BitField("tagged", 1, 1),
                    BitField("addressable", 1, 1),
                    BitField("protocol",1024, 12),
                    LEIntField("source", 248081215),
                  ]

    def post_build(self, p, pay):
        p = p[0:2] + p[3] + p[2]+ p[4:]
        return p+pay

    def pre_dissect(self, s):
        s = s[0:2] + s[3] + s[2]+ s[4:]
        return s

class Lifx_Frame_Address (Packet):
    name = "Lifx Frame Address"
    fields_desc = [
                    LongField("target", 0),
                    BitField("reserved", 0, 48),
                    BitField("reserved", 0, 6),
                    BitField("ack_required", 1, 1),
                    BitField("res_required", 1, 1),
                    ByteField("sequence", 0),
                  ]

class Lifx_Protocol_Header (Packet):
    name = "Lifx Frame Protocol Header"
    fields_desc = [
                    LongField("reserved", 0),
                    LEShortEnumField("type", 2, message_type),
                    LEShortField("reserved", 0),
                  ]

    def answers(self, other):
        if ( ( (self.type ==   3) and (other.type ==   2) ) or
             ( (self.type ==  13) and (other.type ==  12) ) or
             ( (self.type ==  15) and (other.type ==  14) ) or
             ( (self.type ==  17) and (other.type ==  16) ) or
             ( (self.type ==  19) and (other.type ==  18) ) or
             ( (self.type ==  22) and (other.type ==  20) ) or
             ( (self.type ==  25) and (other.type ==  23) ) or
             ( (self.type ==  33) and (other.type ==  32) ) or
             ( (self.type ==  35) and (other.type ==  34) ) or
             ( (self.type ==  50) and (other.type ==  48) ) or
             ( (self.type ==  51) and (other.type ==  53) ) or
             ( (self.type ==  59) and (other.type ==  58) ) or
             ( (self.type == 107) and (other.type == 101) ) or
             ( (self.type == 118) and (other.type == 116) ) ):
            return 1
        return 0

### BINDINGS ###

bind_layers(UDP, Lifx_Frame, sport = 56700)
bind_layers(UDP, Lifx_Frame, dport = 56700)
bind_layers(Lifx_Frame, Lifx_Frame_Address, None )
bind_layers(Lifx_Frame_Address, Lifx_Protocol_Header, None )

### FUNCTIONS ###

def create_lifx_header(dst, type, ack=0, res=0):
    ip   = IP(dst=dst)
    udp  = UDP(sport=56700, dport=56700)
    lifx = (
        Lifx_Frame()/
        Lifx_Frame_Address(ack_required=ack,
                           res_required=res)/
        Lifx_Protocol_Header(type=type)
        )
    packet = (ip/udp/lifx)
    return packet
