"""
blocklist.py

This file just contains the blocklist of the JWT tokens. It will be imported by
app and the logout resource so that tokens can be added to the blocklist when the
user logs out.
"""

"""1) All the blocked tokens (logged out) stored in this file (in set) stays as long as the app runs, 
      because all the blocked list tokens are stored in the local memory
   2) After I log out, 
      the token of the logged out user is in this file, 
      I restart this app, 
      I can use the same logged out token because in this blocked list all the tokens are erased
   3) So we should always store these blocked tokens in a database instead of storing it in local memory"""

BLOCKLIST = set()
