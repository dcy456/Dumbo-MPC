import asyncio
from collections import defaultdict
import logging

from honeybadgermpc.exceptions import RedundantMessageError, AbandonedNodeError
from honeybadgermpc.broadcast.commoncoin import shared_coin
import random
from honeybadgermpc.broadcast.numberagreement import binaryagreement


logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
logger.setLevel(logging.NOTSET)


async def decide(nodeid, n, ba_task, input_msg, broadcast, receive, inputq, outputq):

    # This event is triggered whenever bin_values or aux_values changes
    bv_signal = asyncio.Event()

    async def _recv():
        while True:  # not finished[pid]:
            (sender, msg) = await receive()
            print(sender, msg)
            assert sender in range(n)
            if msg[0] == "time_out":
                inputq.put_nowait(random.randint(2, 3))
                await ba_task
                print(f'NODEID {nodeid} BA VALUE: {await outputq.get()}')
                bv_signal.set()



    # Run the receive loop in the background
    _thread_recv = asyncio.create_task(_recv())
    try:
        # Block waiting for the input
        vi = await input_msg()
        broadcast(("time_out", vi))

        print("----------")

        bv_signal.clear()
        await bv_signal.wait()

            
    finally:
        if asyncio.get_event_loop().is_running():
            _thread_recv.cancel()


async def run_binary_agreement(config, pbk, pvk, n, f, nodeid):
    from honeybadgermpc.broadcast.commoncoin import shared_coin
    import random

    sid_c = "sid_coin"
    sid_de = "sid_de"
    sid_ba = "sid_ba"

    async with ProcessProgramRunner(config, n, f, nodeid) as program_runner:

        send_c, recv_c = program_runner.get_send_recv(sid_c)

        def bcast_c(o):
            for i in range(n):
                send_c(i, o)

        coin, crecv_task = await shared_coin(
            sid_c, nodeid, n, f, pbk, pvk, bcast_c, recv_c
        )

        inputq = asyncio.Queue()
        outputq = asyncio.Queue()

        send_ba, recv_ba = program_runner.get_send_recv(sid_ba)

        def bcast_ba(o):
            for i in range(n):
                send_ba(i, o)

        ba_task = binaryagreement(
            sid_ba,
            nodeid,
            n,
            f,
            coin,
            inputq.get,
            outputq.put_nowait,
            bcast_ba,
            recv_ba,
        )



        decideinputq = asyncio.Queue()

        send_de, recv_de = program_runner.get_send_recv(sid_de)

        def bcast_de(o):
            for i in range(n):
                send_de(i, o)

        decide_task = decide(
            nodeid,
            n,
            ba_task,
            decideinputq.get,
            bcast_de,
            recv_de,
            inputq,
            outputq,
        )
        if nodeid == 1:
            decideinputq.put_nowait(random.randint(2, 3))

        await decide_task


        crecv_task.cancel()


if __name__ == "__main__":
    import pickle
    import base64
    from honeybadgermpc.config import HbmpcConfig
    from honeybadgermpc.ipc import ProcessProgramRunner
    from honeybadgermpc.broadcast.crypto.boldyreva import TBLSPublicKey  # noqa:F401
    from honeybadgermpc.broadcast.crypto.boldyreva import TBLSPrivateKey  # noqa:F401

    pbk = pickle.loads(base64.b64decode(HbmpcConfig.extras["public_key"]))
    pvk = pickle.loads(base64.b64decode(HbmpcConfig.extras["private_key"]))

    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(
            run_binary_agreement(
                HbmpcConfig.peers,
                pbk,
                pvk,
                HbmpcConfig.N,
                HbmpcConfig.t,
                HbmpcConfig.my_id,
            )
        )
    finally:
        loop.close()
