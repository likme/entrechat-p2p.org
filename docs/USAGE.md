# Entrechat — User Guide

## Overview

Entrechat is a peer-to-peer messaging application built on top of Tor.
There are no accounts, no central servers, and no phone numbers.
Your identity exists only on your device.

The application exposes three main sections:
- My Identity
- Contacts
- Options

---

## My Identity

This screen represents your local cryptographic identity.

### Fields

**Identifier**  
A long fingerprint used for human verification.
It should be compared out-of-band with your contact.

**Connection (.onion)**  
Your Tor onion service address.
This is required for peers to reach you.

### Actions

- **Copy**  
  Copies the identifier or onion address.

- **Share my contact**  
  Exports your contact information in a structured format.

- **Show QR**  
  Displays a QR code containing your contact data.
  This is the recommended sharing method.

- **Import a contact**  
  Shortcut to the Contacts section.

- **Refresh**  
  Regenerates or reloads the identity if required.

---

## Contacts

This section manages your peers.

### Actions

- **Import**  
  Import a contact from a file or clipboard.

- **Scan QR**  
  Scan a QR code shared by another Entrechat user.

- **Manual add**  
  Manually enter a contact using:
  - Identifier
  - Onion address
  - Public key (if applicable)

### Self Notes

**Note to self**  
Encrypted local notes.
They are never transmitted over the network.

---

## Options

Application configuration and runtime control.

### General

- **Language**  
  Follows the system language.

- **Security**  
  Enables identity confirmation for contacts.
  Strongly recommended.

### Tor Runtime

Shows the current Tor state.

- **Keep connection active in background**  
  Keeps Tor running with a permanent notification.
  Improves reliability.
  Increases battery usage.

### Tor Controls

- **Restart Tor**  
  Soft restart.

- **Restart Tor (clean)**  
  Full restart cycle.

- **Stop Tor + delete onion**  
  Stops Tor and removes the onion service identity.

---

## Recommended First Use Flow

1. Open **My Identity**
2. Share your QR code with a trusted contact
3. Scan their QR code from **Contacts**
4. Verify identifiers out-of-band
5. Start communicating

---

## Security Model Summary

- Identity is local only
- No central servers
- No metadata storage
- Direct peer-to-peer connections over Tor
- Losing the device may result in identity loss if not backed up

