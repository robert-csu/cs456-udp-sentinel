# Contributions

## Dacovney Brochu
### Part 1:
- Client and Documentation: 
    Implemented the UDP client in C to send test packets to Sentinel using the shared protocol format, including sequential packet numbers, timed packet transmission, and error handling. Tested client functionality by verifying that Sentinel successfully received and accepted all ten packets. Wrote the Adversarial Audit Summary documenting the baseline heartbeat vulnerability to spoofing and explaining how the attack script attempts to exploit unauthenticated heartbeat messages.
### Part 2:
- Client: Updated the UDP client to include a Sentinel state query after sending test packets, added response handling to display the returned hit count, and implemented a 2-second receive timeout. Tested client communication with both the primary and recovered standby, verifying that the hit count was preserved across recovery.

- Written Report: Wrote the redundancy justification explaining the team's choice of passive redundancy, including the trade-offs involving synchronization overhead, implementation complexity, and Mean Time to Repair.

## Robert O'Neil
### Part 1:
- Service:
    Implemented the IPv4 blacklist: creating the txt blacklist, loading it, parsing, and deciding if a packet contains a blacklisted ip and logging it. Created UDP packet filtering on a thread by comparing the packets to a format. Implemented the heartbeat thread to ensure push heartbeats at 500ms. Created the random crash thread to shut down the service at a "random" time given a seed so the monitor can detect a crash. Wrote unit tests using the BCC and mutation analysis results.
### Part 2:
- Service (Recovery):
    Implemented passive redundancy for the Sentinel by using a warm standby with checkpointing. Created a dynamic state module that tracks the blacklists, per-IP packet hit count, and an auto ban that blocks an IP sending more than 20 packets a second. The blacklist is protected by a mutex so there is no race conditions. Created a checkpoint module that saves the state recovery every .5 seconds.
    
## Sam Berman
### Part 1:
Developed the initial monitoring component in C using UDP sockets to receive heartbeat messages from Sentinel.
Implemented heartbeat timeout detection to identify when the primary Sentinel stopped responding.
Added console output to report heartbeat activity and alert when the Sentinel was considered offline.
Helped establish the overall project approach and system architecture.
Participated in testing the monitoring functionality, including demonstrations of heartbeat spoofing and replay attacks.
Recorded demo video
### Part 2:
Extended the monitoring component to support automatic failover when the primary Sentinel stops sending heartbeats.
Implemented replacement process creation using fork() and execl() to launch a standby Sentinel.
Added heartbeat validation using process IDs (PIDs), sequence numbers, and epochs to reject stale or unexpected heartbeat messages.
Implemented recovery event logging for crash detection, failover initiation, and service restoration.
Developed and ran tests to demonstrate how the updated monitor responds to replayed heartbeats, spoofed PIDs, and unauthorized epoch changes.
Assisted with integration testing to verify compatibility between the monitor, checkpointing system, and replacement Sentinel.
Contributed the Execution & Setup Instructions section of the final report.
Prepared and coordinated the video demonstration of the updated monitoring and recovery functionality.

## Tyler Orwa
### Part 1:
- Attacker:
    Implemented the **Heartbeat Spoofer** and **Replay Attack** using Python. The heartbeat spoofer uses forged datagrams sent to the monitor to relay an alive sentinel. The replay attack uses a sniffed heartbeat to replay at the same interval to the monitor to relay an alive sentinel.  Tested functionality of both in sending heartbeats and interacting with the sentinel during runtime. Wrote the '*Service Overview*' and the attacker portion of the '*Execution & Setup Instructions*'
### Part 2:
- Attacker:
    Implemented the **Induced False Failover** script using Python, wrote the Adversarial Audit Summary and the Execution & Setup instructions for the attacker script. The script drops heartbeats to the monitor between its miss window and leaves the primary up and watches for a false failover scenario. It then outputs timestamp markers and a verdict for audit purposes.
