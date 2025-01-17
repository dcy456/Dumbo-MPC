from beaver.config import HbmpcConfig
from beaver.ipc import ProcessProgramRunner, verify_all_connections
from beaver.beaver import BEAVER
import asyncio
import time
from ctypes import *
import json

lib = CDLL("./kzg_ped_out.so")

import pickle
import os

lib.pySampleSecret.argtypes = [c_int]
lib.pySampleSecret.restype = c_char_p

lib.VMmatrixGen.argtypes = [c_int]
lib.VMmatrixGen.restype = c_char_p

async def _run(peers, pbk, pvk, n, t, my_id, batchsize, pks, sk, srs, start_time):
    matrices = lib.VMmatrixGen(t)
    
    async with ProcessProgramRunner(peers, n, t, my_id) as runner:
        send, recv = runner.get_send_recv("")
        with BEAVER(pks, sk, pbk, pvk, n, t, srs, my_id, send, recv, matrices, batchsize) as beaver:
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
    serialized_srs = base64.b64decode(HbmpcConfig.extras["SRS"])
    deserialized_srs_kzg = json.loads(serialized_srs.decode('utf-8'))
    srs = {}
    srs['Pk'] = json.dumps(deserialized_srs_kzg['Pk']).encode('utf-8')
    srs['Vk'] = json.dumps(deserialized_srs_kzg['Vk']).encode('utf-8')
    # loop.run_until_complete(
    #     verify_all_connections(HbmpcConfig.peers, HbmpcConfig.N, HbmpcConfig.my_id)
    #     )
    # print("verification of connection are completed!")

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
