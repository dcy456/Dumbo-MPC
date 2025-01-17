import asyncio
from collections import defaultdict
import logging

from honeybadgermpc.exceptions import RedundantMessageError, AbandonedNodeError


logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
logger.setLevel(logging.NOTSET)

async def decide(n, decide, receive):
    bv_signal = asyncio.Event()
    async def _recv():
        while True:  # not finished[pid]:
            (sender, msg) = await receive()
            assert sender in range(n)
            if msg == "time_out":
                # BV_Broadcast message
                v = "time_out"
                decide(v)
                bv_signal.set()

    # Run the receive loop in the background
    _thread_recv = asyncio.create_task(_recv())
    bv_signal.clear()
    await bv_signal.wait()

    if asyncio.get_event_loop().is_running():
        _thread_recv.cancel()


async def run_binary_agreement(config, pbk, pvk, n, f, nodeid):
    sid_ba = "sid_ba"

    async with ProcessProgramRunner(config, n, f, nodeid) as program_runner:

        outputq = asyncio.Queue()

        send_ba, recv_ba = program_runner.get_send_recv(sid_ba)

        def bcast_ba(o):
            for i in range(n):
                send_ba(i, o)

        de_task = decide(
            n,
            outputq.put_nowait,
            recv_ba,
        )

        _thread_de = asyncio.create_task(de_task)

        if nodeid == 1:
            bcast_ba("time_out")
            # inputq.put_nowait("time_out")

        # await de_task
        # print(await outputq.get())
        msg = await outputq.get()
        print(msg)
        if msg == "time_out":
            print(f'NODEID {nodeid} BA VALUE')


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
