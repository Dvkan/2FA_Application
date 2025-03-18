# 2FA Code and Notification Manager  

## Description  
This is a client-server application written in C/C++ for managing 2FA codes and authentication requests.  
The server generates and stores 2FA codes, which can be requested by the client.  
Authentication requests can be approved or rejected through a client notification system (WIP: No push notifications yet).  

## Features  
- Server generates and manages 2FA codes.  
- Clients can request 2FA codes for authentication.  
- Authentication can be done via:  
  - Entering a valid 2FA code.  
  - Approving/rejecting an authentication request (notification system WIP).  
- Simulated application with authentication options.  

## Technologies Used  
- **Languages:** C/C++  
- **Networking:** Sockets  

## Status  
- Basic 2FA code management and authentication implemented.  
- Notification approval system is a work in progress (no push notifications yet).  

## To-Do  
- Implement push notifications for authentication requests.  
- Improve security and encryption.  
