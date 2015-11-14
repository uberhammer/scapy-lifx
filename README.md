# scapy-lifx

Library to control Lifx bulbs from the command line.

# Background

I don't like the idea of my light bulbs being controlled from the internet, but I still wanted to be able to control them automatically. Here you get the tools to do so without the need of exposing the bulbs to the outside of your local network.

# Usage

You need to run the tool with sudo, as creating network packets needs elevated privileges.

Example:
```sudo ./colortool on 192.168.1.100 0```

# Future Plans

- Discovery Tool (find bulbs in network and show their current settings)
- Control Tool (implements device messages, e.g. get label or wifi information)
- Sunrise Simulation

# References

Protocol Documentation: [lifx-protocol-docs] (https://github.com/LIFX/lifx-protocol-docs)
