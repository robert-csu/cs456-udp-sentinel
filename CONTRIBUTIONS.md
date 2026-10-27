# Contributions

## Dacovney Brochu
- Client and Documentation: 
    Implemented the UDP client in C to send test packets to Sentinel using the shared protocol format, including sequential packet numbers, timed packet transmission, and error handling. Tested client functionality by verifying that Sentinel successfully received and accepted all ten packets. Wrote the Adversarial Audit Summary documenting the baseline heartbeat vulnerability to spoofing and explaining how the attack script attempts to exploit unauthenticated heartbeat messages.

## Robert O'Neil
- Service:
    Implemented the IPv4 blacklist: creating the txt blacklist, loading it, parsing, and deciding if a packet contains a blacklisted ip and logging it. Created UDP packet filtering on a thread by comparing the packets to a format. Implemented the heartbeat thread to ensure push heartbeats at 500ms. Created the random crash thread to shut down the service at a "random" time given a seed so the monitor can detect a crash. Wrote unit tests using the BCC and mutation analysis results.
    
## Sam Berman

## Tyler Orwa
- Attacker:
    Implemented the heartbeat spoofer and replay attack using Python. The heartbeat spoofer uses forged datagrams sent to the monitor to relay an alive sentinel. The replay attack uses a sniffed heartbeat to replay at the same interval to the monitor to relay an alive sentinel.  Tested functionality of both in sending heartbeats and interacting with the sentinel during runtime. Wrote the '*Service Overview*' and the attacker portion of the '*Execution & Setup Instructions*'
