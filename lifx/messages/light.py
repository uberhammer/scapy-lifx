#! /usr/bin/python

from scapy import all
from scapy.all import *
import sys
from ..header import Lifx_Protocol_Header

### PAYLOADS LIGHT ###

class Lifx_Payload_101_Get (Packet):
    name = "Lifx Payload Get"

class Lifx_Payload_102_SetColor (Packet):
    name = "Lifx Payload SetColor"
    fields_desc = [
                    ByteField("reserved", 0),
                    LEShortField("hue", 26478),
                    LEShortField("saturation", 0),
                    LEShortField("brightness", 65535),
                    LEShortField("kelvin", 3500),
                    LEIntField("duration", 0),
                  ]

class Lifx_Payload_107_State (Packet):
    name = "Lifx Payload State"
    fields_desc = [
                    LEShortField("hue", 26478),
                    LEShortField("saturation", 0),
                    LEShortField("brightness", 65535),
                    LEShortField("kelvin", 3500),
                    LEShortField("reserved", 0),
                    LEShortField("power", 0),
                    StrFixedLenField("label", "", 32),
                    BitField("reserved", 0, 64),
                  ]

class Lifx_Payload_116_GetPower (Packet):
    name = "Lifx Payload GetPower"

class Lifx_Payload_117_SetPower (Packet):
    name = "Lifx Payload SetPower"
    fields_desc = [
                    LEShortField("level", 65535),
                    LEIntField("duration", 0),
                  ]

class Lifx_Payload_118_StatePower (Packet):
    name = "Lifx Payload StatePower"
    fields_desc = [
                    LEShortField("level", 0),
                  ]

### BINDINGS ###

bind_layers(Lifx_Protocol_Header, Lifx_Payload_101_Get, type = 101 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_102_SetColor, type = 102 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_107_State, type = 107 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_116_GetPower, type = 116 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_117_SetPower, type = 117 )
bind_layers(Lifx_Protocol_Header, Lifx_Payload_118_StatePower, type = 118 )

