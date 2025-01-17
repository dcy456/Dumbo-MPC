# coding=utf-8
from collections import defaultdict
import zfec
import logging
import hashlib
import math
from beaver.broadcast.crypto.boldyreva import serialize, deserialize1
from ctypes import *
import json
import asyncio


logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
# logger.setLevel(logging.NOTSET)

# TODO: just for benchmarking, this still need for fallback mechanism
async def optimalcommonset(sid, pid, n, f, leader, input, pk, sk, receive, send, acss_outputs, acss_signal):

    def broadcast(o):
        for i in range(n):
            send(i, o)


    if pid == leader:
        # leader broadcasts its input
        broadcast((sid, "1_round", input))

    received = defaultdict(dict)
    
    def contain(set_a, set_b):
        # assert where B contains A
        for i in set_a:
            if i not in set_b:
                return False
        return True


    while True:
        sender, msg = await receive()
        # Every party signs the first signature if leader's input is contained in its input
        if msg[1] == "1_round":
            while True:
                await asyncio.sleep(0.1)
                if contain(msg[2], list(acss_outputs.keys())):
                    # sign the msg[2]
                    h = pk.hash_message(str((sid, "1_round", msg[2])))
                    send(leader, (sid, "2_round", pid, serialize(sk.sign(h))))
                    logging.info(f"--Directly send the proposal!--") 
                    break
                else:
                    logging.info(f"--Wait for the proposal!--") 
                    await acss_signal.wait()
                    acss_signal.clear()
                
        # leader collects the signature shares from at least 2f+1 party, then broadcast the signature
        elif msg[1] == "2_round" and pid == leader:
            assert msg[2] in range(n)
            sig_share = deserialize1(msg[3])
            h = pk.hash_message(str((sid, "1_round", input)))
            try:
                pk.verify_share(sig_share, msg[2], h)
            except AssertionError:
                logger.error(f"Signature share failed! {(sid, leader, msg[2], msg[1])}")
                continue

            received[2][msg[2]] = sig_share

            if len(received[2]) == 2 * f + 1:
                sigs = dict(list(received[2].items())[: f + 1])
                sig = pk.combine_shares(sigs)
                assert pk.verify_signature(sig, h)
                broadcast((sid, "3_round", input, serialize(sig)))


        # Every party verify the signature, and then signs the second (confirmed) signature
        elif msg[1] == "3_round":
            sig = deserialize1(msg[3])
            h = pk.hash_message(str((sid, "1_round", msg[2])))
            assert pk.verify_signature(sig, h)

            h_1 = pk.hash_message(str((sid, "3_round", msg[2])))
            send(leader, (sid, "4_round", pid, serialize(sk.sign(h_1))))

        # leader collects the shares of second signature from at least 2f+1 party, then broadcast the signature
        elif msg[1] == "4_round":
            assert msg[2] in range(n)
            sig_share = deserialize1(msg[3])
            h_1 = pk.hash_message(str((sid, "3_round", input)))
            try:
                pk.verify_share(sig_share, msg[2], h_1)
            except AssertionError:
                logger.error(f"Signature share failed! {(sid, pid, msg[2], msg[1])}")
                continue

            received[4][msg[2]] = sig_share

            if len(received[4]) == 2 * f + 1:
                sigs = dict(list(received[4].items())[: f + 1])
                sig = pk.combine_shares(sigs)
                assert pk.verify_signature(sig, h_1)

                broadcast((sid, "5_round", input, serialize(sig)))

        elif msg[1] == "5_round":
            sig = deserialize1(msg[3])
            h = pk.hash_message(str((sid, "3_round", msg[2])))
            assert pk.verify_signature(sig, h)
            serialized_acsset = json.dumps(list(msg[2])).encode('utf-8')
            
            # lib.pyRandomShareCompute(matrix, serialized_acsset, publickeys, acss_outputs[1], acss_outputs[0], f)

            return msg[2]
