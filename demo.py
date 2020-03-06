from Crypto.Signature import pss
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import secrets
import time

# debug
import sys

# define constants
keySize = 2048
nonceSize = 1024
challengeSize = 8

# generate alice key
alicePrivateKey = RSA.generate(keySize)
alicePublicKey = alicePrivateKey.publickey()

# generate bob key
bobPrivateKey = RSA.generate(keySize)
bobPublicKey = bobPrivateKey.publickey()

# ============================================================================ #
# Alice and Bob want to play rock, papers, scissors without the need of a
# centralized third party to verify each others decisions. This implementation
# prevents cheating via the changing of decisions. After players have exchanged
# some information, one player is left to revealing their nonce before the
# other. In the event that the player who has yet to reveal their nonce is a
# sore loser and opts not to, the player is treated no differently than a player
# who does not choose to show their hand in person.
# ============================================================================ #
# This implementation could be further extended to using a network of nodes
# to verify selection + Nonce combinations to quantify validity in the network.
# There could be a dedicated network of witnesses to watch Alice and Bob
# exchange information prior to the showing of hands. There could be an
# additional network to verify who won.
# ============================================================================ #
# Witness - A connected network of nodes who communicate amongst themselves
# to balance a network of unconnected verifiers with the jobs from players.
# Builder - An unconnected network of nodes who communicate with witnesses to
# assist in the confirmation of a blockchain.
# Verifier - An unconnected network of nodes who communicate with witnesses to
# assist in the verification of a blockchain.
# Player - A node who asks a witness channel to assist in making sure a match
# is properly logged and validated by verifiers

# Alice is seen as the challenger
# Bob is seen as the initiator

print("Bob ACKs")
print("Alice ACKs")

# ============================================================================ #
# Using a challenge phrase ensures that Nonce cannot be fully controlled by a
# single party.
# ============================================================================ #

print("Alice generates and sends a challenge phrase to Bob be inserted anywhere in the nonce")
print("Bob ACKs")

aliceChallenge = secrets.token_bytes(challengeSize)

print("Bob generates and sends a challenge phrase to Alice be inserted anywhere in the nonce")
print("Alice ACKs")

bobChallenge = secrets.token_bytes(challengeSize)

print("Alice sends encrypted hash + a signs the double hash")

# 0:rock, 1:paper, 2:scissors
aliceChallengeOffset = secrets.randbelow(nonceSize - challengeSize)
aliceSelection = secrets.randbelow(3)
aliceNonce = bytearray(secrets.token_bytes(nonceSize))
for index in range(aliceChallengeOffset, aliceChallengeOffset + challengeSize):
    aliceNonce[index] = bobChallenge[index - aliceChallengeOffset]
aliceCombined = bytes(aliceSelection) + aliceNonce
aliceHash = SHA512.new(aliceCombined)
aliceDoubleHash = SHA512.new(aliceHash.digest())
aliceEncryptedMessage = PKCS1_OAEP.new(bobPublicKey).encrypt(aliceHash.digest())
aliceSignature = pss.new(alicePrivateKey).sign(aliceDoubleHash)

print("Bob ACKs")
print("Bob sends encrypted hash + a signs the double hash")

bobChallengeOffset = secrets.randbelow(nonceSize - challengeSize)
bobSelection = secrets.randbelow(3)
bobNonce = bytearray(secrets.token_bytes(nonceSize))
for index in range(bobChallengeOffset, bobChallengeOffset + challengeSize):
    bobNonce[index] = aliceChallenge[index - bobChallengeOffset]
bobCombined = bytes(bobSelection) + aliceNonce
bobHash = SHA512.new(bobCombined)
bobDoubleHash = SHA512.new(bobHash.digest())
bobEncryptedMessage = PKCS1_OAEP.new(alicePublicKey).encrypt(bobHash.digest())
bobSignature = pss.new(bobPrivateKey).sign(bobDoubleHash)

print("Alice ACKs")
print("Alice hashes the encrypted hash from Bob and checks Bob's signature")

aliceDecryptedHash = PKCS1_OAEP.new(alicePrivateKey).decrypt(bobEncryptedMessage)
aliceDecryptedDoubleHash = SHA512.new(aliceDecryptedHash)
try:
    pss.new(bobPublicKey).verify(aliceDecryptedDoubleHash, bobSignature)
    print("Bob's signature passed")
except (ValueError, TypeError):
    print("Bob's signature failed")
aliceDoubleHashSignature = pss.new(alicePrivateKey).sign(aliceDecryptedDoubleHash)

print("Alice sends a signature of the double hash to Bob")
print("Bob ACKs")
print("Bob hashes the encrypted hash from Bob and checks Bob's signature")

bobDecryptedHash = PKCS1_OAEP.new(bobPrivateKey).decrypt(aliceEncryptedMessage)
bobDecryptedDoubleHash = SHA512.new(bobDecryptedHash)
try:
    pss.new(alicePublicKey).verify(bobDecryptedDoubleHash, aliceSignature)
    print("Alice's signature passed")
except (ValueError, TypeError):
    print("Alice's signature failed")
bobDoubleHashSignature = pss.new(bobPrivateKey).sign(bobDecryptedDoubleHash)

print("Bob sends a signature of the double hash to Alice")
print("Alice ACKs")

# ============================================================================ #
# At this point, Alice and Bob could broadcast their signed hashes to a public
# network for permission to reveal nonces, ask for the values to be stored on a
# blockchain prior to Nonce reveals, or simply just
# ============================================================================ #

print("Alice reveals her Nonce value to Bob")
