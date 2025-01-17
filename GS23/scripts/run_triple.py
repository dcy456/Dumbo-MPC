from beaver.config import HbmpcConfig
from beaver.ipc import ProcessProgramRunner, verify_all_connections
from beaver.triple import BEAVER
import asyncio
import time, sys
import logging
from ctypes import *

import pickle

async def _run(peers, pbk, pvk, n, t, my_id, batchsize, pks, sk, srs, start_time):
    
    async with ProcessProgramRunner(peers, n, t, my_id) as runner:
        send, recv = runner.get_send_recv("")
        with BEAVER(pks, sk, pbk, pvk, n, t, srs, my_id, send, recv, None, batchsize) as beaver:
            while True:
                if time.time() > start_time:
                    break
                time.sleep(0.1)
            beaver_task = asyncio.create_task(beaver.run_beaver(runner.node_communicator))
            await beaver_task
            beaver.kill()
            beaver_task.cancel()


if __name__ == "__main__":
    from beaver.config import HbmpcConfig
    HbmpcConfig.load_config()
    
    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    
    from beaver.broadcast.crypto.boldyreva import TBLSPublicKey  # noqa:F401
    from beaver.broadcast.crypto.boldyreva import TBLSPrivateKey  # noqa:F401
    import base64

    pbk = pickle.loads(base64.b64decode(HbmpcConfig.extras["public_key"]))
    pvk = pickle.loads(base64.b64decode(HbmpcConfig.extras["private_key"]))

    pks = base64.b64decode(HbmpcConfig.extras["pks_acss"])
    sk = base64.b64decode(HbmpcConfig.extras["sk_acss"])
    srs = base64.b64decode(HbmpcConfig.extras["SRS"])

    try:
        loop.run_until_complete(
            _run(
                HbmpcConfig.peers,
                pbk,
                pvk,
                HbmpcConfig.N,
                HbmpcConfig.t,
                HbmpcConfig.my_id,
                HbmpcConfig.extras["k"],
                pks, 
                sk,
                srs,
                HbmpcConfig.time
            )
        )
    finally:
        loop.close()
     
    time.sleep(1)
