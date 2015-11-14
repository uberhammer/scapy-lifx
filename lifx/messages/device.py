#! /usr/bin/python

from scapy import all
from scapy.all import *
import sys
import datetime
from ..header import Lifx_Protocol_Header

### FIELDS ###

class LifxTimeField(LELongField):
    def i2h(self, pkt, x):
        epoch = x / 1000000000 # ns to s
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch))

### PAYLOADS DEVICE ###

class Lifx_Payload_2_GetService (Packet):
    name = "Lifx Payload GetService"

class Lifx_Payload_3_StateService (Packet):
    name = "Lifx Payload StateService"
    fields_desc = [
                    ByteField("service", 0),
                    LEIntField("port", 0),
                  ]

class Lifx_Payload_12_GetHostInfo (Packet):
    name = "Lifx Payload GetHostInfo"

class Lifx_Payload_13_StateHostInfo (Packet):
    name = "Lifx Payload StateHostInfo"
    fields_desc = [
                    IEEEFloatField("signal", 0), #TODO: (32 bit) check endianness, check fieldtype
                    LEIntField("tx", 0),
                    LEIntField("rx", 0),
                    LEShortField("reserved", 0),
                  ]

class Lifx_Payload_14_GetHostFirmware (Packet):
    name = "Lifx Payload GetHostFirmware"

class Lifx_Payload_15_StateHostFirmware (Packet):
    name = "Lifx Payload StateHostFirmware"
    fields_desc = [
                    LELongField("build", 0),
                    LELongField("reserved", 0),
                    LEIntField("version", 0),
                  ]

class Lifx_Payload_16_GetWifiInfo (Packet):
    name = "Lifx Payload GetWifiInfo"

class Lifx_Payload_17_StateWifiInfo (Packet):
    name = "Lifx Payload StateWifiInfo"
    fields_desc = [
                    IEEEFloatField("signal", 0), #TODO: (32 bit) check endianness, check fieldtype
                    LEIntField("tx", 0),
                    LEIntField("rx", 0),
                    LEShortField("reserved", 0),
                  ]

class Lifx_Payload_18_GetWifiFirmware (Packet):
    name = "Lifx Payload GetWifiFirmware"

class Lifx_Payload_19_StateWifiFirmware (Packet):
    name = "Lifx Payload StateWifiFirmware"
    fields_desc = [
                    LELongField("build", 0),
                    LELongField("reserved", 0),
                    LEIntField("version", 0),
                  ]

class Lifx_Payload_20_GetPower (Packet):
    name = "Lifx Payload GetPower"

class Lifx_Payload_21_SetPower (Packet):
    name = "Lifx Payload SetPower"
    fields_desc = [
                    LEShortField("level", 0),
                  ]

class Lifx_Payload_22_StatePower (Packet):
    name = "Lifx Payload StatePower"
    fields_desc = [
                    LEShortField("level", 0),
                  ]

class Lifx_Payload_23_GetLabel (Packet):
    name = "Lifx Payload GetLabel"

class Lifx_Payload_24_SetLabel (Packet):
    name = "Lifx Payload SetLabel"
    fields_desc = [
                    StrFixedLenField("label", "", 32),
                  ]

class Lifx_Payload_25_StateLabel (Packet):
    name = "Lifx Payload StateLabel"
    fields_desc = [
                    StrFixedLenField("label", "", 32),
                  ]

class Lifx_Payload_32_GetVersion (Packet):
    name = "Lifx Payload GetVersion"

class Lifx_Payload_33_StateVersion (Packet):
    name = "Lifx Payload StateVersion"
    fields_desc = [
                    LEIntField("vendor", 0),
                    LEIntField("product", 0),
                    LEIntField("version", 0),
                  ]

class Lifx_Payload_34_GetInfo (Packet):
    name = "Lifx Payload GetInfo"

class Lifx_Payload_35_StateInfo (Packet):
    name = "Lifx Payload StateInfo"
    fields_desc = [
                    LELongField("time", 0),
                    LELongField("uptime", 0),
                    LELongField("downtime", 0),
                  ]

class Lifx_Payload_45_Acknowledgement (Packet):
    name = "Lifx Payload Acknowledgement"

class Lifx_Payload_48_GetLocation (Packet):
    name = "Lifx Payload GetLocation"

class Lifx_Payload_50_StateLocation (Packet):
    name = "Lifx Payload StateLocation"
    fields_desc = [
                    BitField("location", 0, 16*8), #TODO
                    StrFixedLenField("label", "", 32),
                    LifxTimeField("updated_at", 0),
                  ]

class Lifx_Payload_51_GetGroup (Packet):
    name = "Lifx Payload GetGroup"

class Lifx_Payload_53_StateGroup (Packet):
    name = "Lifx Payload StateGroup"
    fields_desc = [
                    BitField("location", 0, 16*8), #TODO
                    StrFixedLenField("label", "", 32),
                    LifxTimeField("updated_at", 0),
                  ]

class Lifx_Payload_58_EchoRequest (Packet):
    name = "Lifx Payload EchoRequest"
    fields_desc = [
                    StrFixedLenField("load","",64)
                  ]

class Lifx_Payload_59_EchoResponse (Packet):
    name = "Lifx Payload EchoResponse"
    fields_desc = [
                    StrFixedLenField("load","",64)
                  ]

### BINDINGS ###

bind_layers(Lifx_Protocol_Header, Lifx_Payload_2_GetService, type = 2 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_3_StateService, type = 3 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_12_GetHostInfo, type = 12 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_13_StateHostInfo, type = 13 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_14_GetHostFirmware, type = 14 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_15_StateHostFirmware, type = 15 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_16_GetWifiInfo, type = 16 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_17_StateWifiInfo, type = 17 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_18_GetWifiFirmware, type = 18 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_19_StateWifiFirmware, type = 19 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_20_GetPower, type = 20 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_21_SetPower, type = 21 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_22_StatePower, type = 22 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_23_GetLabel, type = 23 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_24_SetLabel, type = 24 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_25_StateLabel, type = 25 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_32_GetVersion, type = 32 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_33_StateVersion, type = 33 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_34_GetInfo, type = 34 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_35_StateInfo, type = 35 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_45_Acknowledgement, type = 45 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_48_GetLocation, type = 48 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_50_StateLocation, type = 50 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_51_GetGroup, type = 51 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_53_StateGroup, type = 53 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_58_EchoRequest, type = 58 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_59_EchoResponse, type = 59 )

