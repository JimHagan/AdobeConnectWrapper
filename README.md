# AdobeConnectWrapper
## A Python API wrapper and abstraction layer for the AdobeConnect XML API

AdobeConnect is a powerful interactive learning platform that consists of a "learning space" comprised of video conference, chat, virtual whiteboard and file sharing capabilities. 

### Basic code hierarchy

- **adobe_connect.py** A very thin wrapper to the Adobe Connect XML API (Use this for a simple and granular one-to-one interface)
- **meeting_management.py** A set of higher level abstractions for integrating Adobe Connect into an application (Use this for a more object oriented encapsulation of connect).
- **tests.py** Tests covering major classes from both adobe_connect.py and meeting_management.py

*NOTE*: This code was extracted from a larger codebase and there may be some loose ends which would prevent it function as is, but it would be trivial to get it working in it's minimal state.

### More information on AdobeConnect

- [Platform Overview](http://www.adobe.com/products/adobeconnect/learning.html?sdid=7WQ4666H&mv=search&s_kwcid=AL!3085!3!79456083022!b!!g!!adobe%20connect&ef_id=VD8QvQAABYGvw1En:20160227014107:s]) 
- [XML API Reference](http://help.adobe.com/en_US/connect/8.0/webservices/connect_8_webservices.pdf)

