import asyncio
from optimizedhbmpc.config import HbmpcConfig
import time
import logging
from optimizedhbmpc.field import GF
from optimizedhbmpc.elliptic_curve import Subgroup
from optimizedhbmpc.polynomial import EvalPoint, polynomials_over
from optimizedhbmpc.reed_solomon import EncoderFactory, DecoderFactory
from optimizedhbmpc.mpc import Mpc
from optimizedhbmpc.ipc import ProcessProgramRunner
from optimizedhbmpc.utils.misc import (
    wrap_send,
    transpose_lists,
    flatten_lists,
    subscribe_recv,
)
from optimizedhbmpc.field import GF
from optimizedhbmpc.elliptic_curve import Subgroup
from optimizedhbmpc.broadcast.commoncoin import shared_coin
from optimizedhbmpc.broadcast.numberagreement import binaryagreement

class HyperInvMessageType(object):
    SUCCESS = True
    ABORT = False
    
async def _recv_loop(recv, n, s=0):
    results = [None] * n
    for _ in range(n):
        sender_id, value = await recv()
        results[sender_id - s] = value
        
    return results

    
async def randousha(n, t, k, my_id,  _send, _recv, field, round, bcast, dual_mode=False):
    """
    Generates a batch of (n-2t)k secret sharings of random elements
    """            
    poly = polynomials_over(field)
    eval_point = EvalPoint(field, n, use_omega_powers=False)
    big_t = n - (2 * t) - 1  # This is same as `T` in the HyperMPC paper.
    encoder = EncoderFactory.get(eval_point)
    # Pick k random elements
    def to_int(coeffs):
        return tuple(map(int, coeffs))
        
    my_randoms = [field.random() for _ in range(k)]
    
    # Generate t and 2t shares of the random element.
    coeffs_t = [to_int(poly.random(t, r).coeffs) for r in my_randoms]
    coeffs_2t = [to_int(poly.random(2 * t, r).coeffs) for r in my_randoms]
    unref_t = encoder.encode(coeffs_t)    
    unref_2t = encoder.encode(coeffs_2t)

    subscribe_recv_task, subscribe = subscribe_recv(_recv)
    # Start listening for my share of t and 2t shares from all parties.
    def _get_send_recv(tag):
        return wrap_send(tag, _send), subscribe(tag)

    # Start listening for my share of t and 2t shares from all parties.
    send_H1, recv_H1 = _get_send_recv(str(round)+"H1")
    share_recv_task = asyncio.create_task(_recv_loop(recv_H1, n))

    # Send each party their shares.
    to_send_t = transpose_lists(unref_t)
    to_send_2t = transpose_lists(unref_2t)
    for i in range(n):
        send_H1(i, (to_send_t[i], to_send_2t[i]))

    # Wait until all shares are received.
    received_shares = await share_recv_task
    unrefined_t_shares, unrefined_2t_shares = zip(*received_shares)

    # Apply the hyper-invertible matrix.
    # Assume the unrefined shares to be coefficients of a polynomial
    # and then evaluate that polynomial at powers of omega.
    ref_t = encoder.encode(transpose_lists(list(unrefined_t_shares)))
    ref_2t = encoder.encode(transpose_lists(list(unrefined_2t_shares)))

    # Parties with id in [N-2t+1, N] need to start
    # listening for shares which they have to check.
    send, recv = _get_send_recv(str(round)+"H2")
    to_send_t = transpose_lists(ref_t)
    to_send_2t = transpose_lists(ref_2t)

    if my_id > big_t:
        share_chk_recv_task = asyncio.create_task(_recv_loop(recv, n))

    # Send shares of parties with id in [N-2t+1, N] to those parties.
    for i in range(big_t + 1, n):
        send(i, (to_send_t[i], to_send_2t[i]))
    
    # Parties with id in [N-2t+1, N] need to verify that the shares are in-fact correct.
    if my_id > big_t:
        shares_to_check = await share_chk_recv_task
        shares_t, shares_2t = zip(*shares_to_check)
        # self.response = HyperInvMessageType.ABORT

        def get_degree(p):
            for i in range(len(p))[::-1]:
                if p[i] != 0:
                    return i
            return 0

        def get_degree_and_secret(shares):
            decoder = DecoderFactory.get(eval_point)
            polys = decoder.decode(list(range(n)), transpose_lists(list(shares)))
            secrets = [p[0] for p in polys]
            degrees = [get_degree(p) for p in polys]
            return degrees, secrets

        degree_t, secret_t = get_degree_and_secret(shares_t)
        degree_2t, secret_2t = get_degree_and_secret(shares_2t)

        # Verify that the shares are in-fact `t` and `2t` shared.
        # Verify that both `t` and `2t` shares of the same value.
        if not (
            all(deg == t for deg in degree_t)
            and all(deg == 2 * t for deg in degree_2t)
            and secret_t == secret_2t
        ):
            check = HyperInvMessageType.ABORT
        
        # simulate check failure        
        if dual_mode and round == 10:
            check = HyperInvMessageType.ABORT
            bcast("Check failed")

    if my_id < big_t:
        await asyncio.sleep(0.5)
        
    
    subscribe_recv_task.cancel()

    out_t = flatten_lists([s[: big_t + 1] for s in ref_t])
    out_2t = flatten_lists([s[: big_t + 1] for s in ref_2t])

    return tuple(zip(out_t, out_2t))


async def OptRanTriGen(n, t, k, my_id, _send, _recv, field, round, bcast=None, dual_mode=False):
    subscribe_recv_task, subscribe = subscribe_recv(_recv)       
    def _get_send_recv(tag):
        return wrap_send(tag, _send), subscribe(tag)

    # Start listening for my share of t and 2t shares from all parties.
    send, recv = _get_send_recv(str(round)+"randousha")
    rs_t2t = await randousha(n, t, 3 * k, my_id,  send, recv, field, round, bcast, dual_mode)

    as_t2t = rs_t2t[0 * k : 1 * k]
    bs_t2t = rs_t2t[1 * k : 2 * k]
    rs_t2t = rs_t2t[2 * k : 3 * k]

    as_t, _ = zip(*as_t2t)
    bs_t, _ = zip(*bs_t2t)
    as_t = list(map(field, as_t))
    bs_t = list(map(field, bs_t))
    rs_t, rs_2t = zip(*rs_t2t)


    # Compute degree reduction to get triples
    # TODO: Use the mixins and preprocessing system
    async def prog(ctx):
        assert len(rs_2t) == len(rs_t) == len(as_t) == len(bs_t)

        abrs_2t = [a * b + r for a, b, r in zip(as_t, bs_t, rs_2t)]
        abrs = await ctx.ShareArray(abrs_2t, 2 * t).open()
        abs_t = [abr - r for abr, r in zip(abrs, rs_t)]
        return list(zip(as_t, bs_t, abs_t))

    # TODO: compute triples through degree reduction
    send, recv = _get_send_recv(str(round)+"opening")
    ctx = Mpc(f"mpc:opening", n, t, my_id, send, recv, prog, {})

    result = await ctx._run()
    
    # simulate time expires
    # if self.my_id == 1 and self.round == 10:
    #     await asyncio.sleep(50)
    
    subscribe_recv_task.cancel()
    
    return result

async def _run(peers, pbk, pvk, n, t, k, my_id, max_timeout = 0.5):
    global logger 
    logfile = f'./log/logs-{my_id}.log'
    logger = logging.getLogger(__name__)
    logging.basicConfig(
        level=logging.INFO, 
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  
        datefmt='%Y-%m-%d %H:%M:%S',
        filename=logfile,  
        filemode='w'
        )
    field = GF(Subgroup.BLS12_381)
    async with ProcessProgramRunner(peers, n, t, my_id) as runner:
        logger.info(f'[{my_id}] start OptRanTriGen')
        send, recv = runner.get_send_recv("")
        def bcast(o):
            for i in range(n):
                send(i, o)
        start_opt_time = time.time() 
        total_round = 10   
        for round in range(total_round):
            start_round_time = time.time()
            triples = await OptRanTriGen(n, t, k, my_id, send, recv, field, round, bcast=None, dual_mode=False)
            logger.info(f'[{my_id}] finished {round}-th OptRanTriGen instance, time: {time.time()-start_round_time}')

        logger.info(f'[{my_id}] Finished OptRanTriGen! triples: {k * total_round}, time: {time.time()-start_opt_time} (seconds)')

        bytes_sent = runner.node_communicator.bytes_sent
        logger.info(f"[{my_id}] Total bytes sent out aa: {bytes_sent}")



if __name__ == "__main__":

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



        