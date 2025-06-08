# FiveM Auto Reconnect

**FiveM Auto Reconnect** is a Windows utility written in C++ that monitors your connection to a FiveM server and automatically attempts to reconnect if the connection is lost.

## 🧠 Features

- **Automatic connection detection** using `netstat`
- **Time-based connection logic**: connects only within a specified time window
- **Auto-relaunches FiveM** if disconnected from the server
- **Automatically closes FiveM** outside of configured hours
- **Discord notifications** via webhook (connection status updates)

## 💡 How to Find the Server IP Address and Port

To correctly configure the `target_ip` and `target_port` fields, follow these steps:
1. Connect to the FiveM server manually using the FiveM client.
2. Open Command Prompt by pressing `Win + R`, typing `cmd`, and pressing Enter.
3. Run the following command to list all network connections and find the server IP/port that is in the ESTABLISHED state, only when you are connected to the server.
   ```bash
   netstat -n

## ⚙️ Example Configuration for Baylife server (`config.json`)
```json
{
    "end_hour": 16,
    "end_minute": 55,
    "server_url": "fivem://connect/9zj5ay",
    "start_hour": 17,
    "start_minute": 5,
    "target_ip": "51.210.203.140",
    "target_port": "64738",
    "webhook_url": "https://discord.com/api/webhooks/..."
}
