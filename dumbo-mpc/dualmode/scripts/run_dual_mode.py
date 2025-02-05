# import os
# import sys
# sys.path.append('/usr/local/lib/python3.8/dist-packages')
# current_directory = os.getcwd()
# print("当前工作目录:", current_directory)

import asyncio
import logging
from optimizedhbmpc.config import HbmpcConfig
from optimizedhbmpc.ipc import ProcessProgramRunner
from dual_mode import dualmode

async def _run(peers, pbk, pvk, n, t, k, my_id):
    async with ProcessProgramRunner(peers, n, t, my_id) as runner:
        send, recv = runner.get_send_recv("")
        with dualmode(pbk, pvk, n, t, my_id, k, send, recv) as dm:
            dm_task = asyncio.create_task(dm.run_dualmode(runner.node_communicator))
            await dm_task
            dm_task.cancel()

if __name__ == "__main__":
    import os
    import sys
    sys.path.append('/usr/local/lib/python3.8/dist-packages')

    import pickle
    import base64
    from optimizedhbmpc.broadcast.crypto.boldyreva import TBLSPublicKey  # noqa:F401
    from optimizedhbmpc.broadcast.crypto.boldyreva import TBLSPrivateKey  # noqa:F401
    pbk = pickle.loads(base64.b64decode(HbmpcConfig.extras["public_key"]))
    pvk = pickle.loads(base64.b64decode(HbmpcConfig.extras["private_key"]))

    asyncio.set_event_loop(asyncio.new_event_loop())
    
    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        _run(
            HbmpcConfig.peers,
            pbk,
            pvk,
            HbmpcConfig.N,
            HbmpcConfig.t,
            HbmpcConfig.extras["k"],
            HbmpcConfig.my_id,
        )
    )