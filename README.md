# GameNet

GameNet exposes a local **TCP** game server through a public relay. The player connects to a TCP port on the relay; the relay forwards that traffic to the host agent over an encrypted QUIC connection. The player-to-relay connection is not encrypted by GameNet.

Run `gamenet host minecraft` or `gamenet host --port 7777`. The relay chooses an available TCP port from `10000..=10999` and prints the address to share. It binds the port before announcing it. If the host disconnects, GameNet holds that port for five minutes and the running CLI retries automatically. After five minutes, the next registration may get a different port.


UDP games such as Minecraft Bedrock and Valheim are not supported yet. A UDP-only preset returns an error instead of creating a nonworking TCP tunnel.

The relay's QUIC listener uses UDP port `5000`. A production relay should set both `GAMENET_TLS_CERT` and `GAMENET_TLS_KEY` to its certificate and key files. The relay state file contains expiring token fingerprints rather than bearer tokens. On first startup with the older permanent-reservation file, GameNet creates an owner-only `gamenet-state.json.legacy-backup`; that backup still contains bearer tokens and should be removed after the migration is verified.
