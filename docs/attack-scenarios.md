# Attack Scenarios

## IDOR

Bob attempts to read Globex's document by guessing its UUID. The API denies the request before returning document content because the document tenant does not match Bob's tenant.

## Stale JWT

Alice grants Bob viewer access, Bob receives a JWT, and Alice later revokes Bob's viewer tuple. Bob's unchanged JWT no longer works because the next request checks OpenFGA.

## Wrong-IP Delegated Link

Alice creates a delegated token with an IP caveat. A request from a different IP fails caveat validation before document data is returned.

## Expired Delegated Link

A delegated token whose `expires_before` caveat is in the past is denied.

## Revoked Issuer Delegation

Alice issues a delegated token and then loses access to the document. The delegated token stops working because the delegated endpoint performs a live OpenFGA check for Alice.

