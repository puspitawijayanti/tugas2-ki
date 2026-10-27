# Assignment 2 Information Security: Key Distribution Scenario (KDC)

Implementation of the key distribution scenario (KDC, Alice, Bob) on three different hosts using AES-128 (ECB and CBC).

## Files and hosts

Windows host (KDC):
- `aes.py`
- `kdc.py`

Alice VM:
- `aes.py`
- `node.py`

Bob VM:
- `aes.py`
- `node.py`

`aes.py` holds AES-128, ECB/CBC, padding, and shared helpers. `kdc.py` is the key distribution center. `node.py` is used by both Alice and Bob.

## How to run

1. KDC (Windows), then enter the master keys for alice and bob:
   ```
   python kdc.py
   ```
2. Bob (Bob VM):
   ```
   python3 node.py bob [IP-HOST-KDC]
   ```
3. Alice (Alice VM):
   ```
   python3 node.py alice [IP-HOST-KDC]
   ```
4. On Alice choose `1` (Start session), then enter Peer ID `bob`, Peer IP `[ip bob]`, and press Enter for the default port.
5. Choose `2` to chat. Type `/menu` to go back to the menu.


## Screenshots
![](/images/0.png)
![](/images/1.png)
![](/images/2.png)
![](/images/3.png)
![](/images/4.png)
![](/images/5.png)